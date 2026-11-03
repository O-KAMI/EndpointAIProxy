package control

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"endpointai/client/internal/contracts"
	"endpointai/client/internal/observability"
	"endpointai/client/internal/protocol"

	"github.com/google/uuid"
)

type Options struct {
	Origin, EnrollmentToken, CertificatePin, TransportKeyID string
	PolicyKey, PolicyPublicKey, TransportKey                []byte
}
type Client struct {
	Options                   Options
	HTTP                      *http.Client
	Observe                   func(string, observability.Detail, time.Duration)
	deviceMu                  sync.RWMutex
	deviceTransportID         string
	deviceTransportV2ID       string
	deviceTransportV2Key      [32]byte
	deviceTransportGeneration uint64
	deviceTokenHash           [32]byte
	deviceStore               DeviceTransportStore
	deviceStoreErr            error
}

// DeviceTransportStore stores an authenticated, platform-protected negotiation state.
type DeviceTransportStore interface {
	LoadDeviceTransport(context.Context) (string, error)
	SaveDeviceTransport(context.Context, string) error
}

type persistedDeviceTransport struct {
	Origin    string `json:"origin"`
	Pin       string `json:"pin"`
	Device    string `json:"device"`
	KeyID     string `json:"keyId"`
	Key       []byte `json:"key"`
	TokenHash []byte `json:"tokenHash"`
}

// AttachDeviceTransportStore restores the V2 key before any control request. A
// changed server identity requires explicit recovery rather than silent fallback.
func (c *Client) AttachDeviceTransportStore(ctx context.Context, store DeviceTransportStore) (failure error) {
	defer func() { c.deviceStoreErr = failure }()
	if store == nil {
		return errors.New("CONTROL_DEVICE_STORE_INVALID")
	}
	value, err := store.LoadDeviceTransport(ctx)
	if err != nil {
		return errors.New("CONTROL_DEVICE_STORE_READ_FAILED")
	}
	if value != "" {
		var saved persistedDeviceTransport
		if json.Unmarshal([]byte(value), &saved) != nil || saved.Origin != c.Options.Origin || saved.Pin != c.Options.CertificatePin || !strings.HasPrefix(c.Options.Origin, "https://") || len(saved.TokenHash) != sha256.Size {
			return errors.New("CONTROL_DEVICE_STORE_INVALID")
		}
		if _, ok := c.HTTP.Transport.(*protocol.Transport); !ok {
			return errors.New("CONTROL_DEVICE_STORE_INVALID")
		}
		generation, err := protocol.ValidateDeviceV2Key(saved.Device, saved.KeyID, saved.Key)
		if err != nil {
			return errors.New("CONTROL_DEVICE_STORE_INVALID")
		}
		c.deviceTransportID, c.deviceTransportV2ID, c.deviceTransportGeneration = saved.Device, saved.KeyID, generation
		copy(c.deviceTransportV2Key[:], saved.Key)
		copy(c.deviceTokenHash[:], saved.TokenHash)
		clear(saved.Key)
	}
	c.deviceStore = store
	return nil
}

// HTTPError is produced only for authenticated business responses when encrypted transport is in use.
type HTTPError struct {
	Status     int
	RetryAfter time.Duration
}

func (e *HTTPError) Error() string { return fmt.Sprintf("CONTROL_HTTP_%d", e.Status) }

func New(opts Options) (*Client, error) {
	u, e := url.Parse(opts.Origin)
	if e != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || opts.EnrollmentToken == "" ||
		!((len(opts.PolicyPublicKey) == 0 && len(opts.PolicyKey) >= 32) || (len(opts.PolicyPublicKey) == 32 && len(opts.PolicyKey) == 0)) {
		return nil, errors.New("CONTROL_CONFIGURATION_INVALID")
	}
	opts.Origin = strings.TrimRight(opts.Origin, "/") + "/"
	base := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second}
	var transport http.RoundTripper = base
	if len(opts.TransportKey) > 0 {
		if (u.Scheme != "http" && u.Scheme != "https") || len(opts.TransportKey) != 32 || !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(opts.TransportKeyID) {
			return nil, errors.New("CONTROL_TRANSPORT_CONFIGURATION_INVALID")
		}
	}
	if u.Scheme == "https" {
		pin, e := base64.StdEncoding.DecodeString(opts.CertificatePin)
		if e != nil || len(pin) != 32 {
			return nil, errors.New("CONTROL_TLS_PIN_INVALID")
		}
		// The existing protocol trusts an explicitly pinned RSA key, including private/self-signed
		// certificates. Replace chain validation, never hostname, validity or key validation.
		base.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("CONTROL_TLS_PIN_MISMATCH")
			}
			cert := cs.PeerCertificates[0]
			if e := cert.VerifyHostname(u.Hostname()); e != nil {
				return errors.New("CONTROL_TLS_HOST_MISMATCH")
			}
			now := time.Now()
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return errors.New("CONTROL_TLS_CERTIFICATE_EXPIRED")
			}
			if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
				return errors.New("CONTROL_TLS_PIN_MISMATCH")
			}
			actual := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(pin, actual[:]) != 1 {
				return errors.New("CONTROL_TLS_PIN_MISMATCH")
			}
			return nil
		}}
	} else if len(opts.TransportKey) == 0 {
		return nil, errors.New("CONTROL_TLS_PIN_INVALID")
	}
	if len(opts.TransportKey) > 0 {
		transport = &protocol.Transport{Base: base, MasterKey: opts.TransportKey, KeyID: opts.TransportKeyID, ServerOrigin: opts.Origin}
	}
	return &Client{Options: opts, HTTP: &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) call(ctx context.Context, method, path, token string, in, out any) (headers http.Header, data []byte, failure error) {
	started := time.Now()
	trace := &protocol.Trace{}
	ctx = protocol.WithTrace(ctx, trace)
	requestPath := strings.SplitN(path, "?", 2)[0]
	stage := "enroll"
	switch {
	case strings.HasSuffix(requestPath, "/policy"):
		stage = "policy"
	case requestPath == "/api/v2/heartbeat" || requestPath == "/api/v2/heartbeat/light" || requestPath == "/api/v2/heartbeat/light-compact":
		stage = "heartbeat"
	case strings.HasSuffix(path, "/events/batch"):
		stage = "events"
	case strings.HasSuffix(path, "/status"):
		stage = "command_receipt"
	case strings.Contains(requestPath, "/credential/"):
		stage = "credential_rotation"
	}
	defer func() {
		d := observability.Classify(failure)
		if d.Stage == "" {
			d.Stage = stage
		}
		d.ControlRequestID = trace.ControlRequestID
		if headers != nil {
			d.ServerRequestID = observability.SafeID(headers.Get("X-Request-ID"))
		}
		if d.ServerRequestID == "" {
			d.ServerRequestID = trace.ServerRequestID
		}
		var status *HTTPError
		if errors.As(failure, &status) {
			d.HTTPStatus = status.Status
			d.Class = "HTTP"
			d.Code = "CONTROL_HTTP_FAILED"
		}
		if failure != nil {
			if d.Code == "" {
				d.Code = "CONTROL_REQUEST_FAILED"
			}
			failure = &observability.Error{Detail: d, Cause: failure}
		}
		if c.Observe != nil {
			c.Observe(stage, d, time.Since(started))
		}
	}()
	if c.deviceStoreErr != nil {
		return nil, nil, errors.New("CONTROL_DEVICE_STORE_UNAVAILABLE")
	}
	var body io.Reader
	if in != nil {
		b, e := json.Marshal(in)
		if e != nil {
			return nil, nil, e
		}
		body = bytes.NewReader(b)
	}
	r, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Options.Origin, "/")+path, body)
	if e != nil {
		return nil, nil, errors.New("CONTROL_REQUEST_INVALID")
	}
	if token == "" {
		token = c.Options.EnrollmentToken
	}
	if token == "" {
		return nil, nil, errors.New("CONTROL_ENROLLMENT_TOKEN_MISSING")
	}
	if requestPath != "/api/v2/enroll" {
		c.deviceMu.RLock()
		device, keyID, key, tokenHash := c.deviceTransportID, c.deviceTransportV2ID, c.deviceTransportV2Key, c.deviceTokenHash
		c.deviceMu.RUnlock()
		if keyID != "" {
			actual := sha256.Sum256([]byte(token))
			if subtle.ConstantTimeCompare(actual[:], tokenHash[:]) != 1 {
				return nil, nil, errors.New("CONTROL_DEVICE_TOKEN_CHANGED")
			}
			deviceCtx, keyErr := protocol.WithDeviceV2Key(r.Context(), device, keyID, key[:])
			if keyErr != nil {
				return nil, nil, keyErr
			}
			r = r.WithContext(deviceCtx)
		} else if device != "" {
			r = r.WithContext(protocol.WithDeviceIdentity(r.Context(), device))
		}
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Accept", "application/json")
	if in != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	res, e := c.HTTP.Do(r)
	if e != nil {
		return nil, nil, observability.Wrap("control_connect", "CONTROL_CONNECTION_FAILED", e)
	}
	defer res.Body.Close()
	headers = res.Header
	if trace.ControlRequestID != "" {
		headers.Set("X-EndpointAI-Local-Envelope-ID", trace.ControlRequestID)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		retry := time.Duration(0)
		if seconds, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && seconds > 0 && seconds <= 300 {
			retry = time.Duration(seconds) * time.Second
		}
		return res.Header, nil, &HTTPError{Status: res.StatusCode, RetryAfter: retry}
	}
	limit := int64(30_000_000)
	if strings.HasSuffix(requestPath, "/policy") {
		limit = 1024 * 1024
	} else if strings.Contains(requestPath, "/credential/") {
		limit = 16 * 1024
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if e != nil {
		return res.Header, nil, observability.Wrap("control_read", "CONTROL_RESPONSE_INVALID", e)
	}
	if int64(len(b)) > limit {
		return res.Header, nil, &observability.Error{Detail: observability.Detail{Stage: "control_read", Class: "PAYLOAD_LIMIT", Code: "CONTROL_RESPONSE_INVALID"}}
	}
	if out != nil {
		if e = json.Unmarshal(b, out); e != nil {
			return res.Header, nil, observability.Wrap("control_decode", "CONTROL_RESPONSE_INVALID", e)
		}
	}
	return res.Header, b, nil
}

func (c *Client) Enroll(ctx context.Context, in contracts.DeviceEnrollmentRequest) (contracts.DeviceEnrollmentResponse, error) {
	var out contracts.DeviceEnrollmentResponse
	initial := in
	initial.PreviousDeviceToken = ""
	initial.PreserveDeviceToken = false
	headers, _, e := c.call(ctx, "POST", "/api/v2/enroll", "", initial, &out)
	var status *HTTPError
	if errors.As(e, &status) && status.Status == http.StatusConflict && in.PreviousDeviceToken != "" {
		in.PreserveDeviceToken = true
		headers, _, e = c.call(ctx, "POST", "/api/v2/enroll", "", in, &out)
	}
	if e == nil && (out.DeviceID != in.DeviceID || out.DeviceToken == "" || out.EnrolledAtUTC.IsZero()) {
		e = responseFailure("enroll_validate", "CONTROL_ENROLLMENT_INVALID", nil, headers)
	}
	return out, e
}
func (c *Client) Policy(ctx context.Context, device, token string, stateless ...bool) (contracts.Policy, string, error) {
	policy, signature, _, err := c.PolicyRaw(ctx, device, token, stateless...)
	return policy, signature, err
}

// PolicyRaw preserves exactly the bytes authenticated by the server for offline verification.
func (c *Client) PolicyRaw(ctx context.Context, device, token string, stateless ...bool) (contracts.Policy, string, []byte, error) {
	var out contracts.Policy
	query := "?policySchemaVersion=2"
	if len(stateless) > 0 && stateless[0] {
		query += "&statelessPolicyVersions=1"
	}
	if len(c.Options.PolicyPublicKey) > 0 {
		query += "&policySignature=ed25519-v1"
	}
	headers, b, e := c.call(ctx, "GET", "/api/v2/devices/"+device+"/policy"+query, token, nil, nil)
	if e != nil {
		return out, "", nil, e
	}
	sig := headers.Get("X-SF-Policy-Signature")
	if len(c.Options.PolicyPublicKey) > 0 {
		e = protocol.VerifyEd25519(b, sig, c.Options.PolicyPublicKey, "policy")
	} else {
		e = protocol.Verify(b, sig, c.Options.PolicyKey)
	}
	if e != nil {
		return out, "", nil, responseFailure("policy_verify", "POLICY_SIGNATURE_INVALID", e, headers)
	}
	if e = json.Unmarshal(b, &out); e != nil {
		return out, "", nil, responseFailure("policy_decode", "POLICY_BODY_INVALID", e, headers)
	}
	if e = protocol.ValidatePolicy(out); e != nil {
		return out, "", nil, responseFailure("policy_validate", "POLICY_INVALID", e, headers)
	}
	return out, sig, b, nil
}
func (c *Client) Heartbeat(ctx context.Context, in contracts.HeartbeatV2Request, token string) (contracts.HeartbeatV2Response, error) {
	var out contracts.HeartbeatV2Response
	in.Ed25519Signatures = len(c.Options.PolicyPublicKey) > 0
	if strings.HasPrefix(c.Options.Origin, "https://") && c.Options.CertificatePin != "" {
		_, in.DeviceTransportV2 = c.HTTP.Transport.(*protocol.Transport)
	} else {
		in.DeviceTransportV2 = false
	}
	_, rotationStore := c.deviceStore.(CredentialRotationStore)
	in.CredentialRotationV1 = in.DeviceTransportV2 && rotationStore
	path := "/api/v2/heartbeat"
	if in.InventoryUnchanged {
		if in.CompactInventory {
			path += "/light-compact"
		} else {
			path += "/light"
		}
	}
	headers, _, e := c.call(ctx, "POST", path, token, in, &out)
	if e == nil && out.Command != nil {
		e = c.VerifyCommand(*out.Command)
		if e != nil {
			e = responseFailure("command_verify", "COMMAND_SIGNATURE_INVALID", e, headers)
		}
	}
	if e == nil && (out.DeviceTransport || out.DeviceTransportV2 != nil) && strings.HasPrefix(c.Options.Origin, "https://") && c.Options.CertificatePin != "" {
		if _, ok := c.HTTP.Transport.(*protocol.Transport); ok {
			device := in.Device.DeviceID
			id, parseErr := uuid.Parse(device)
			if parseErr != nil || id == uuid.Nil || id.String() != device || len(token) < 16 || len(token) > 512 {
				e = errors.New("CONTROL_DEVICE_IDENTITY_INVALID")
			} else {
				var generation uint64
				if out.DeviceTransportV2 != nil {
					generation, e = protocol.ValidateDeviceV2Key(device, out.DeviceTransportV2.KeyID, out.DeviceTransportV2.Key)
				}
				if e == nil {
					c.deviceMu.Lock()
					if c.deviceTransportID != "" && c.deviceTransportID != device {
						e = errors.New("CONTROL_DEVICE_IDENTITY_CHANGED")
					} else if out.DeviceTransportV2 != nil && generation == c.deviceTransportGeneration && generation != 0 && subtle.ConstantTimeCompare(c.deviceTransportV2Key[:], out.DeviceTransportV2.Key) != 1 {
						e = errors.New("CONTROL_DEVICE_KEY_GENERATION_CONFLICT")
					} else {
						if out.DeviceTransportV2 != nil && generation > c.deviceTransportGeneration {
							tokenHash := sha256.Sum256([]byte(token))
							if c.deviceStore != nil {
								saved := persistedDeviceTransport{Origin: c.Options.Origin, Pin: c.Options.CertificatePin, Device: device, KeyID: out.DeviceTransportV2.KeyID, Key: out.DeviceTransportV2.Key, TokenHash: tokenHash[:]}
								var data []byte
								data, e = json.Marshal(saved)
								if e == nil {
									e = c.deviceStore.SaveDeviceTransport(ctx, string(data))
									clear(data)
								}
								if e != nil {
									e = errors.New("CONTROL_DEVICE_STORE_WRITE_FAILED")
								}
							}
							if e == nil {
								c.deviceTransportV2ID = out.DeviceTransportV2.KeyID
								c.deviceTransportGeneration = generation
								c.deviceTokenHash = tokenHash
								copy(c.deviceTransportV2Key[:], out.DeviceTransportV2.Key)
							}
						}
						if e == nil {
							c.deviceTransportID = device
						}
					}
					c.deviceMu.Unlock()
				}
			}
		}
	}
	if out.DeviceTransportV2 != nil {
		for i := range out.DeviceTransportV2.Key {
			out.DeviceTransportV2.Key[i] = 0
		}
		out.DeviceTransportV2 = nil
	}
	return out, e
}

func (c *Client) VerifyCommand(command contracts.SignedRemoteCommand) error {
	if len(c.Options.PolicyPublicKey) > 0 {
		return protocol.VerifyCommandEd25519(command, c.Options.PolicyPublicKey)
	}
	return protocol.VerifyCommand(command, c.Options.PolicyKey)
}
func (c *Client) CommandStatus(ctx context.Context, in contracts.RemoteCommandStatusUpdate, token string) error {
	_, _, e := c.call(ctx, "POST", "/api/v2/commands/"+in.CommandID+"/status", token, in, nil)
	return e
}
func (c *Client) Events(ctx context.Context, in contracts.EventBatchRequest, token string) (contracts.EventBatchResponse, error) {
	var out contracts.EventBatchResponse
	_, _, e := c.call(ctx, "POST", "/api/v2/events/batch", token, in, &out)
	return out, e
}

func responseFailure(stage, code string, cause error, headers http.Header) error {
	d := observability.Classify(cause)
	d.Stage = stage
	d.Code = code
	d.ControlRequestID = observability.SafeID(headers.Get("X-EndpointAI-Local-Envelope-ID"))
	d.ServerRequestID = observability.SafeID(headers.Get("X-Request-ID"))
	if strings.Contains(code, "SIGNATURE") {
		d.Class = "SIGNATURE_INVALID"
	} else if d.Class == "" || d.Class == "OTHER" {
		d.Class = "CONTRACT_INVALID"
	}
	return &observability.Error{Detail: d, Cause: cause}
}

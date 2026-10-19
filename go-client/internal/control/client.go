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
	"strings"
	"time"

	"endpointai/client/internal/contracts"
	"endpointai/client/internal/observability"
	"endpointai/client/internal/protocol"
)

type Options struct {
	Origin, EnrollmentToken, CertificatePin, TransportKeyID string
	PolicyKey, TransportKey                                 []byte
}
type Client struct {
	Options Options
	HTTP    *http.Client
	Observe func(string, observability.Detail, time.Duration)
}

// HTTPError is produced only for authenticated business responses when encrypted transport is in use.
type HTTPError struct{ Status int }

func (e *HTTPError) Error() string { return fmt.Sprintf("CONTROL_HTTP_%d", e.Status) }

func New(opts Options) (*Client, error) {
	u, e := url.Parse(opts.Origin)
	if e != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || len(opts.PolicyKey) < 32 || opts.EnrollmentToken == "" {
		return nil, errors.New("CONTROL_CONFIGURATION_INVALID")
	}
	opts.Origin = strings.TrimRight(opts.Origin, "/") + "/"
	base := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ForceAttemptHTTP2: true, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second}
	var transport http.RoundTripper = base
	if len(opts.TransportKey) > 0 {
		if u.Scheme != "http" || len(opts.TransportKey) != 32 || !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(opts.TransportKeyID) {
			return nil, errors.New("CONTROL_TRANSPORT_CONFIGURATION_INVALID")
		}
		transport = &protocol.Transport{Base: base, MasterKey: opts.TransportKey, KeyID: opts.TransportKeyID, ServerOrigin: opts.Origin}
	} else {
		pin, e := base64.StdEncoding.DecodeString(opts.CertificatePin)
		if u.Scheme != "https" || e != nil || len(pin) != 32 {
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
	}
	return &Client{Options: opts, HTTP: &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) call(ctx context.Context, method, path, token string, in, out any) (headers http.Header, data []byte, failure error) {
	started := time.Now()
	trace := &protocol.Trace{}
	ctx = protocol.WithTrace(ctx, trace)
	stage := "enroll"
	switch {
	case strings.HasSuffix(path, "/policy"):
		stage = "policy"
	case strings.HasSuffix(path, "/heartbeat"):
		stage = "heartbeat"
	case strings.HasSuffix(path, "/events/batch"):
		stage = "events"
	case strings.HasSuffix(path, "/status"):
		stage = "command_receipt"
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
		return res.Header, nil, &HTTPError{res.StatusCode}
	}
	limit := int64(30_000_000)
	if strings.HasSuffix(path, "/policy") {
		limit = 1024 * 1024
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
	headers, _, e := c.call(ctx, "POST", "/api/v2/enroll", "", in, &out)
	if e == nil && (out.DeviceID != in.DeviceID || out.DeviceToken == "" || out.EnrolledAtUTC.IsZero()) {
		e = responseFailure("enroll_validate", "CONTROL_ENROLLMENT_INVALID", nil, headers)
	}
	return out, e
}
func (c *Client) Policy(ctx context.Context, device, token string) (contracts.Policy, string, error) {
	var out contracts.Policy
	headers, b, e := c.call(ctx, "GET", "/api/v2/devices/"+device+"/policy", token, nil, nil)
	if e != nil {
		return out, "", e
	}
	sig := headers.Get("X-SF-Policy-Signature")
	if e = protocol.Verify(b, sig, c.Options.PolicyKey); e != nil {
		return out, "", responseFailure("policy_verify", "POLICY_SIGNATURE_INVALID", e, headers)
	}
	if e = json.Unmarshal(b, &out); e != nil {
		return out, "", responseFailure("policy_decode", "POLICY_BODY_INVALID", e, headers)
	}
	if e = protocol.ValidatePolicy(out); e != nil {
		return out, "", responseFailure("policy_validate", "POLICY_INVALID", e, headers)
	}
	return out, sig, nil
}
func (c *Client) Heartbeat(ctx context.Context, in contracts.HeartbeatV2Request, token string) (contracts.HeartbeatV2Response, error) {
	var out contracts.HeartbeatV2Response
	headers, _, e := c.call(ctx, "POST", "/api/v2/heartbeat", token, in, &out)
	if e == nil && out.Command != nil {
		e = protocol.VerifyCommand(*out.Command, c.Options.PolicyKey)
		if e != nil {
			e = responseFailure("command_verify", "COMMAND_SIGNATURE_INVALID", e, headers)
		}
	}
	return out, e
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

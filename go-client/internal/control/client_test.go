package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	stdhex "encoding/hex"
	"encoding/json"
	"encoding/pem"
	"endpointai/client/internal/contracts"
	"endpointai/client/internal/observability"
	"endpointai/client/internal/protect"
	"endpointai/client/internal/protocol"
	"endpointai/client/internal/state"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func pinnedTestServer(t *testing.T, hostname string, expired bool) (*httptest.Server, string) {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	end := now.Add(time.Hour)
	if expired {
		end = now.Add(-time.Hour)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, NotBefore: now.Add(-2 * time.Hour), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if e != nil {
		t.Fatal(e)
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"accepted":0,"duplicates":0,"rejected":0,"errors":[]}`))
	}))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	s.StartTLS()
	parsed, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	return s, base64.StdEncoding.EncodeToString(sum[:])
}
func TestPinnedSelfSignedTLSRejectsHostnameExpiryAndWrongPin(t *testing.T) {
	for _, test := range []struct {
		name, hostname                 string
		expired, wrongPin, wantSuccess bool
	}{{"selfsigned", "127.0.0.1", false, false, true}, {"hostname", "wrong.invalid", false, false, false}, {"expiry", "127.0.0.1", true, false, false}, {"pin", "127.0.0.1", false, true, false}} {
		t.Run(test.name, func(t *testing.T) {
			s, pin := pinnedTestServer(t, test.hostname, test.expired)
			defer s.Close()
			if test.wrongPin {
				pin = base64.StdEncoding.EncodeToString(make([]byte, 32))
			}
			c, e := New(Options{Origin: s.URL, EnrollmentToken: "synthetic", PolicyKey: make([]byte, 32), CertificatePin: pin})
			if e != nil {
				t.Fatal(e)
			}
			_, e = c.Events(context.Background(), contracts.EventBatchRequest{}, "synthetic")
			if (e == nil) != test.wantSuccess {
				t.Fatalf("got %v success=%v", e, test.wantSuccess)
			}
		})
	}
}

func TestEncryptedTransportOverPinnedTLS(t *testing.T) {
	for _, test := range []struct {
		name, hostname                 string
		expired, wrongPin, wantSuccess bool
	}{{"valid", "127.0.0.1", false, false, true}, {"hostname", "wrong.invalid", false, false, false}, {"expired", "127.0.0.1", true, false, false}, {"wrong-pin", "127.0.0.1", false, true, false}} {
		t.Run(test.name, func(t *testing.T) {
			s, pin := pinnedTestServer(t, test.hostname, test.expired)
			defer s.Close()
			if test.wrongPin {
				pin = base64.StdEncoding.EncodeToString(make([]byte, 32))
			}
			key := bytes.Repeat([]byte{7}, 32)
			var received atomic.Int32
			s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received.Add(1)
				if r.URL.Path != "/api/transport/v1" {
					t.Error("unexpected outer path")
					return
				}
				var envelope protocol.Envelope
				if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
					t.Error(err)
					return
				}
				plain, err := protocol.Open(key, "test", envelope.RequestID, envelope, "request")
				if err != nil {
					t.Error(err)
					return
				}
				var inner protocol.InnerRequest
				if err = json.Unmarshal(plain, &inner); err != nil || inner.Token != "synthetic-device" || inner.Path != "/api/v2/events/batch" {
					t.Error("unexpected encrypted request")
					return
				}
				body := base64.StdEncoding.EncodeToString([]byte(`{"accepted":0,"duplicates":0,"rejected":0,"errors":[]}`))
				reply, _ := json.Marshal(protocol.InnerResponse{Status: 200, Body: body, Headers: map[string]string{"Content-Type": "application/json"}})
				sealed, err := protocol.Seal(key, "test", envelope.RequestID, reply, "response")
				if err != nil {
					t.Error(err)
					return
				}
				_ = json.NewEncoder(w).Encode(sealed)
			})
			c, err := New(Options{Origin: s.URL, EnrollmentToken: "synthetic", PolicyKey: key, TransportKey: key, TransportKeyID: "test", CertificatePin: pin})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Events(context.Background(), contracts.EventBatchRequest{}, "synthetic-device")
			if (err == nil) != test.wantSuccess || (received.Load() > 0) != test.wantSuccess {
				t.Fatalf("transport result=%v received=%d", err, received.Load())
			}
		})
	}
	if _, err := New(Options{Origin: "https://example.invalid", EnrollmentToken: "synthetic", PolicyKey: make([]byte, 32), TransportKey: make([]byte, 32), TransportKeyID: "test"}); err == nil {
		t.Fatal("encrypted HTTPS accepted without a certificate pin")
	}
}
func TestEncryptedOuter401IsNotBusinessUnauthorized(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer s.Close()
	c, e := New(Options{Origin: s.URL, EnrollmentToken: "synthetic", PolicyKey: make([]byte, 32), TransportKey: make([]byte, 32), TransportKeyID: "test"})
	if e != nil {
		t.Fatal(e)
	}
	_, e = c.Events(context.Background(), contracts.EventBatchRequest{}, "token")
	var httpErr *HTTPError
	if e == nil || errors.As(e, &httpErr) {
		t.Fatalf("untrusted outer response produced business status: %v", e)
	}
}

func TestEnrollmentSendsExistingCredentialOnlyAfterConflict(t *testing.T) {
	var requests []contracts.DeviceEnrollmentRequest
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request contracts.DeviceEnrollmentRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requests = append(requests, request)
		if len(requests) == 1 {
			w.WriteHeader(http.StatusConflict)
			return
		}
		json.NewEncoder(w).Encode(contracts.DeviceEnrollmentResponse{DeviceID: request.DeviceID, DeviceToken: "new-synthetic-token", EnrolledAtUTC: time.Now().UTC()})
	}))
	defer s.Close()
	c := &Client{Options: Options{Origin: s.URL, EnrollmentToken: "synthetic-bootstrap"}, HTTP: s.Client()}
	out, err := c.Enroll(context.Background(), contracts.DeviceEnrollmentRequest{DeviceID: "synthetic-device", PreviousDeviceToken: "synthetic-old-token"})
	if err != nil || out.DeviceToken != "new-synthetic-token" {
		t.Fatalf("enrollment failed: %v", err)
	}
	if len(requests) != 2 || requests[0].PreviousDeviceToken != "" || requests[0].PreserveDeviceToken || requests[1].PreviousDeviceToken != "synthetic-old-token" || !requests[1].PreserveDeviceToken {
		t.Fatal("credential proof did not follow authenticated conflict")
	}
}

func TestEncryptedRetryAfterIsAuthenticatedAndBounded(t *testing.T) {
	key := make([]byte, 32)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request protocol.Envelope
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		body, err := json.Marshal(protocol.InnerResponse{Status: 503, Body: "", Headers: map[string]string{"Retry-After": "60"}})
		if err != nil {
			t.Error(err)
			return
		}
		response, err := protocol.Seal(key, "test", request.RequestID, body, "response")
		if err != nil {
			t.Error(err)
			return
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer s.Close()
	c, err := New(Options{Origin: s.URL, EnrollmentToken: "synthetic", PolicyKey: key, TransportKey: key, TransportKeyID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Events(context.Background(), contracts.EventBatchRequest{}, "synthetic")
	var result *HTTPError
	if !errors.As(err, &result) || result.Status != 503 || result.RetryAfter != time.Minute {
		t.Fatalf("authenticated retry signal missing: %v", err)
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, &net.DNSError{Err: "synthetic-secret", Name: "synthetic-secret-host", IsNotFound: true}
}
func TestControlNetworkEvidenceDoesNotLeakCause(t *testing.T) {
	c := &Client{Options: Options{Origin: "https://synthetic.invalid", EnrollmentToken: "synthetic-token"}, HTTP: &http.Client{Transport: failingTransport{}}}
	_, err := c.Events(context.Background(), contracts.EventBatchRequest{}, "synthetic-token")
	d := observability.Classify(err)
	if d.Class != "DNS_NOT_FOUND" || d.Stage != "control_connect" {
		t.Fatal(d)
	}
	encoded, _ := json.Marshal(observability.Fields(d))
	if strings.Contains(string(encoded), "synthetic-secret") || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatal("raw error persisted")
	}
}

func TestEnrollmentCanRetryAfterPreservedResponseIsLost(t *testing.T) {
	var proofs int
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request contracts.DeviceEnrollmentRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if request.PreviousDeviceToken == "" {
			w.WriteHeader(http.StatusConflict)
			return
		}
		if request.PreviousDeviceToken != "synthetic-old-token" || !request.PreserveDeviceToken {
			t.Error("retry did not request preservation of the old credential")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		proofs++
		if proofs == 1 {
			w.Header().Set("Content-Length", "512")
			_, _ = w.Write([]byte("{")) // Simulate a response lost after the server committed.
			return
		}
		_ = json.NewEncoder(w).Encode(contracts.DeviceEnrollmentResponse{DeviceID: request.DeviceID, DeviceToken: request.PreviousDeviceToken, EnrolledAtUTC: time.Now().UTC()})
	}))
	defer s.Close()
	c := &Client{Options: Options{Origin: s.URL, EnrollmentToken: "synthetic-bootstrap"}, HTTP: s.Client()}
	request := contracts.DeviceEnrollmentRequest{DeviceID: "synthetic-device", PreviousDeviceToken: "synthetic-old-token"}
	if _, err := c.Enroll(context.Background(), request); err == nil {
		t.Fatal("truncated response was accepted")
	}
	out, err := c.Enroll(context.Background(), request)
	if err != nil || out.DeviceToken != request.PreviousDeviceToken || proofs != 2 {
		t.Fatalf("retry failed: proofs=%d err=%v", proofs, err)
	}
}

func TestDeviceTransportNegotiationUsesPinnedTLSAndNeverFallsBack(t *testing.T) {
	const device = "11111111-2222-4333-8444-555555555555"
	const token = "synthetic-device-token-1234567890"
	const deviceID = "dv1_11111111222243338444555555555555"
	master, err := stdhex.DecodeString("4b70d6d084f7b137a74034ff407c481d0bbbd14a1fef24a6017d18b82d78b894")
	if err != nil {
		t.Fatal(err)
	}
	shared := bytes.Repeat([]byte{7}, 32)
	s, pin := pinnedTestServer(t, "127.0.0.1", false)
	defer s.Close()
	var ids []string
	var reject atomic.Bool
	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var envelope protocol.Envelope
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			t.Error(err)
			return
		}
		ids = append(ids, envelope.KeyID)
		key := shared
		if envelope.KeyID == deviceID {
			key = master
		}
		if reject.Load() {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		plain, err := protocol.Open(key, envelope.KeyID, envelope.RequestID, envelope, "request")
		if err != nil {
			t.Error(err)
			return
		}
		var request protocol.InnerRequest
		if err := json.Unmarshal(plain, &request); err != nil || request.Token != token {
			t.Error("invalid bound request")
			return
		}
		body := []byte(`{"accepted":0,"duplicates":0,"rejected":0,"errors":[]}`)
		if strings.HasSuffix(request.Path, "/heartbeat") {
			body = []byte(`{"deviceTransport":true}`)
		}
		inner, _ := json.Marshal(protocol.InnerResponse{Status: 200, Body: base64.StdEncoding.EncodeToString(body), Headers: map[string]string{"Content-Type": "application/json"}})
		sealed, err := protocol.Seal(key, envelope.KeyID, envelope.RequestID, inner, "response")
		if err != nil {
			t.Error(err)
			return
		}
		_ = json.NewEncoder(w).Encode(sealed)
	})
	c, err := New(Options{Origin: s.URL, EnrollmentToken: "synthetic-enrollment", PolicyKey: shared, TransportKey: shared, TransportKeyID: "test", CertificatePin: pin})
	if err != nil {
		t.Fatal(err)
	}
	beat := contracts.HeartbeatV2Request{Device: contracts.DeviceIdentity{DeviceID: device}}
	if _, err := c.Heartbeat(context.Background(), beat, token); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Events(context.Background(), contracts.EventBatchRequest{}, token); err != nil {
		t.Fatal(err)
	}
	reject.Store(true)
	if _, err := c.Events(context.Background(), contracts.EventBatchRequest{}, token); err == nil {
		t.Fatal("rejected bound transport unexpectedly succeeded")
	}
	if strings.Join(ids, ",") != "test,"+deviceID+","+deviceID {
		t.Fatalf("unexpected key selection: %v", ids)
	}
}

func TestDeviceTransportCapabilityDoesNotActivateOnHTTP(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	var ids []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var envelope protocol.Envelope
		_ = json.NewDecoder(r.Body).Decode(&envelope)
		ids = append(ids, envelope.KeyID)
		body := base64.StdEncoding.EncodeToString([]byte(`{"deviceTransport":true}`))
		inner, _ := json.Marshal(protocol.InnerResponse{Status: 200, Body: body, Headers: map[string]string{}})
		sealed, _ := protocol.Seal(key, envelope.KeyID, envelope.RequestID, inner, "response")
		_ = json.NewEncoder(w).Encode(sealed)
	}))
	defer s.Close()
	c, err := New(Options{Origin: s.URL, EnrollmentToken: "synthetic", PolicyKey: key, TransportKey: key, TransportKeyID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	beat := contracts.HeartbeatV2Request{Device: contracts.DeviceIdentity{DeviceID: "11111111-2222-4333-8444-555555555555"}}
	if _, err := c.Heartbeat(context.Background(), beat, "synthetic-device-token-1234567890"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Events(context.Background(), contracts.EventBatchRequest{}, "synthetic-device-token-1234567890"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(ids, ",") != "test,test" {
		t.Fatalf("HTTP negotiated device transport: %v", ids)
	}
}

func TestInvalidSignedCommandCannotEnableDeviceTransport(t *testing.T) {
	shared := bytes.Repeat([]byte{7}, 32)
	s, pin := pinnedTestServer(t, "127.0.0.1", false)
	defer s.Close()
	var ids []string
	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var envelope protocol.Envelope
		_ = json.NewDecoder(r.Body).Decode(&envelope)
		ids = append(ids, envelope.KeyID)
		plain, err := protocol.Open(shared, "test", envelope.RequestID, envelope, "request")
		if err != nil {
			t.Error(err)
			return
		}
		var request protocol.InnerRequest
		_ = json.Unmarshal(plain, &request)
		body := []byte(`{"accepted":0,"duplicates":0,"rejected":0,"errors":[]}`)
		if strings.HasSuffix(request.Path, "/heartbeat") {
			body = []byte(`{"deviceTransport":true,"command":{"payload":{},"signature":"invalid"}}`)
		}
		inner, _ := json.Marshal(protocol.InnerResponse{Status: 200, Body: base64.StdEncoding.EncodeToString(body), Headers: map[string]string{}})
		sealed, _ := protocol.Seal(shared, "test", envelope.RequestID, inner, "response")
		_ = json.NewEncoder(w).Encode(sealed)
	})
	c, err := New(Options{Origin: s.URL, EnrollmentToken: "synthetic", PolicyKey: shared, TransportKey: shared, TransportKeyID: "test", CertificatePin: pin})
	if err != nil {
		t.Fatal(err)
	}
	beat := contracts.HeartbeatV2Request{Device: contracts.DeviceIdentity{DeviceID: "11111111-2222-4333-8444-555555555555"}}
	token := "synthetic-device-token-1234567890"
	if _, err := c.Heartbeat(context.Background(), beat, token); err == nil {
		t.Fatal("invalid signature accepted")
	}
	if _, err := c.Events(context.Background(), contracts.EventBatchRequest{}, token); err != nil {
		t.Fatal(err)
	}
	if strings.Join(ids, ",") != "test,test" {
		t.Fatalf("invalid response enabled device transport: %v", ids)
	}
}

type failingDeviceStore struct {
	DeviceTransportStore
	fail bool
}

func (s *failingDeviceStore) SaveDeviceTransport(ctx context.Context, value string) error {
	if s.fail {
		return errors.New("synthetic disk failure")
	}
	return s.DeviceTransportStore.SaveDeviceTransport(ctx, value)
}

func TestDeviceTransportV2RotationOverlapAndNoDowngrade(t *testing.T) {
	const device = "11111111-2222-4333-8444-555555555555"
	const token = "synthetic-device-token-1234567890"
	const firstID = "dv2_1_11111111222243338444555555555555"
	const secondID = "dv2_2_11111111222243338444555555555555"
	shared, first, second := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{31}, 32), bytes.Repeat([]byte{32}, 32)
	s, pin := pinnedTestServer(t, "127.0.0.1", false)
	defer s.Close()
	var ids []string
	var generation atomic.Int32
	var conflict atomic.Bool
	var omitV2 atomic.Bool
	var reject atomic.Bool
	generation.Store(1)
	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var envelope protocol.Envelope
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			t.Error(err)
			return
		}
		ids = append(ids, envelope.KeyID)
		if reject.Load() {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		key := shared
		switch envelope.KeyID {
		case firstID:
			key = first
		case secondID:
			key = second
		case "test":
		default:
			t.Error("unexpected key ID")
			return
		}
		plain, err := protocol.Open(key, envelope.KeyID, envelope.RequestID, envelope, "request")
		if err != nil {
			t.Error(err)
			return
		}
		var request protocol.InnerRequest
		if json.Unmarshal(plain, &request) != nil || request.Token != token {
			t.Error("unexpected request")
			return
		}
		body := []byte(`{"accepted":0,"duplicates":0,"rejected":0,"errors":[]}`)
		if strings.HasSuffix(request.Path, "/heartbeat") {
			chosenID, chosenKey := firstID, first
			if generation.Load() == 2 {
				chosenID, chosenKey = secondID, second
			}
			if conflict.Load() {
				chosenKey = bytes.Repeat([]byte{99}, 32)
			}
			body, _ = json.Marshal(map[string]any{"deviceTransport": true, "deviceTransportV2": map[string]any{"keyId": chosenID, "key": chosenKey}})
			if omitV2.Load() {
				body = []byte(`{"deviceTransport":true}`)
			}
		}
		inner, _ := json.Marshal(protocol.InnerResponse{Status: 200, Body: base64.StdEncoding.EncodeToString(body), Headers: map[string]string{}})
		sealed, err := protocol.Seal(key, envelope.KeyID, envelope.RequestID, inner, "response")
		if err != nil {
			t.Error(err)
			return
		}
		_ = json.NewEncoder(w).Encode(sealed)
	})
	c, err := New(Options{Origin: s.URL, EnrollmentToken: "synthetic", PolicyKey: shared, TransportKey: shared, TransportKeyID: "test", CertificatePin: pin})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	protector, err := protect.NewFileKey(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "state.db")
	store, err := state.Open(dbPath, protector)
	if err != nil {
		t.Fatal(err)
	}
	failing := &failingDeviceStore{DeviceTransportStore: store, fail: true}
	if err = c.AttachDeviceTransportStore(context.Background(), failing); err != nil {
		t.Fatal(err)
	}
	beat := contracts.HeartbeatV2Request{Device: contracts.DeviceIdentity{DeviceID: device}}
	heartbeat := func() error {
		out, e := c.Heartbeat(context.Background(), beat, token)
		if out.DeviceTransportV2 != nil {
			t.Fatal("derived key escaped to application")
		}
		return e
	}
	events := func() {
		if _, e := c.Events(context.Background(), contracts.EventBatchRequest{}, token); e != nil {
			t.Fatal(e)
		}
	}
	if err := heartbeat(); err == nil {
		t.Fatal("state write failure accepted")
	}
	if c.deviceTransportV2ID != "" {
		t.Fatal("uncommitted key activated")
	}
	failing.fail = false
	if err := heartbeat(); err != nil {
		t.Fatal(err)
	}
	events()
	generation.Store(2)
	if err := heartbeat(); err != nil {
		t.Fatal(err)
	}
	events()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = state.Open(dbPath, protector)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	c, err = New(Options{Origin: s.URL, EnrollmentToken: "synthetic", PolicyKey: shared, TransportKey: shared, TransportKeyID: "test", CertificatePin: pin})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.AttachDeviceTransportStore(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Events(context.Background(), contracts.EventBatchRequest{}, "different-device-token-123456789"); err == nil {
		t.Fatal("changed token accepted")
	}
	wrong, err := New(Options{Origin: s.URL, EnrollmentToken: "synthetic", PolicyKey: shared, TransportKey: shared, TransportKeyID: "test", CertificatePin: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	if err = wrong.AttachDeviceTransportStore(context.Background(), store); err == nil {
		t.Fatal("changed server pin accepted")
	}
	if _, err = wrong.Events(context.Background(), contracts.EventBatchRequest{}, token); err == nil {
		t.Fatal("failed state restoration allowed a control request")
	}
	generation.Store(1)
	if err := heartbeat(); err != nil {
		t.Fatal(err)
	}
	events()
	omitV2.Store(true)
	if err := heartbeat(); err != nil {
		t.Fatal(err)
	}
	events()
	omitV2.Store(false)
	generation.Store(2)
	conflict.Store(true)
	if err := heartbeat(); err == nil {
		t.Fatal("same generation with different key accepted")
	}
	events()
	reject.Store(true)
	if _, err := c.Events(context.Background(), contracts.EventBatchRequest{}, token); err == nil {
		t.Fatal("rejected device key unexpectedly succeeded")
	}
	want := []string{"test", "test", firstID, firstID, secondID, secondID, secondID, secondID, secondID, secondID, secondID, secondID}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("unexpected key sequence: %v", ids)
	}
}

func TestInvalidDeviceV2KeyDoesNotFallBackToV1(t *testing.T) {
	shared := bytes.Repeat([]byte{7}, 32)
	s, pin := pinnedTestServer(t, "127.0.0.1", false)
	defer s.Close()
	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var envelope protocol.Envelope
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			t.Error(err)
			return
		}
		body, _ := json.Marshal(map[string]any{"deviceTransport": true, "deviceTransportV2": map[string]any{
			"keyId": "dv2_1_aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa", "key": bytes.Repeat([]byte{42}, 32)}})
		inner, _ := json.Marshal(protocol.InnerResponse{Status: 200, Body: base64.StdEncoding.EncodeToString(body), Headers: map[string]string{}})
		sealed, err := protocol.Seal(shared, "test", envelope.RequestID, inner, "response")
		if err != nil {
			t.Error(err)
			return
		}
		_ = json.NewEncoder(w).Encode(sealed)
	})
	c, err := New(Options{Origin: s.URL, EnrollmentToken: "synthetic", PolicyKey: shared, TransportKey: shared, TransportKeyID: "test", CertificatePin: pin})
	if err != nil {
		t.Fatal(err)
	}
	beat := contracts.HeartbeatV2Request{Device: contracts.DeviceIdentity{DeviceID: "11111111-2222-4333-8444-555555555555"}}
	out, err := c.Heartbeat(context.Background(), beat, "synthetic-device-token-1234567890")
	if err == nil || out.DeviceTransportV2 != nil || c.deviceTransportID != "" || c.deviceTransportV2ID != "" {
		t.Fatal("invalid key accepted or fell back")
	}
}

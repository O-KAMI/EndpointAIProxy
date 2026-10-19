package control

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"endpointai/client/internal/contracts"
	"endpointai/client/internal/observability"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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

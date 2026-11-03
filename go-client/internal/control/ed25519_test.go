package control

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"endpointai/client/internal/contracts"
	"endpointai/client/internal/protocol"
)

func TestPublicKeyNegotiationRejectsLegacyPolicyAndCommand(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	private := ed25519.NewKeyFromSeed(seed)
	var fixture struct{ PolicyBody, CommandBody string }
	b, err := os.ReadFile("../protocol/testdata/dotnet-v0.1.19.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	var command contracts.RemoteCommandPayload
	if err := json.Unmarshal([]byte(fixture.CommandBody), &command); err != nil {
		t.Fatal(err)
	}
	canonical, err := protocol.CommandBody(command)
	if err != nil || string(canonical) != fixture.CommandBody {
		t.Fatalf("command mismatch: %v", err)
	}
	sign := func(purpose string, body []byte) string {
		message := append([]byte("sf-endpointai-"+purpose+"-ed25519-v1\n"), body...)
		return "ed25519-v1:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))
	}
	var downgrade atomic.Bool
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/policy") {
			if r.URL.Query().Get("policySignature") != "ed25519-v1" {
				t.Error("missing policy negotiation")
			}
			sig := sign("policy", []byte(fixture.PolicyBody))
			if downgrade.Load() {
				sig, _ = protocol.Sign([]byte(fixture.PolicyBody), seed)
			}
			w.Header().Set("X-SF-Policy-Signature", sig)
			_, _ = w.Write([]byte(fixture.PolicyBody))
			return
		}
		var h contracts.HeartbeatV2Request
		if err := json.NewDecoder(r.Body).Decode(&h); err != nil || !h.Ed25519Signatures {
			t.Error("missing command negotiation", err)
		}
		sig := sign("command", canonical)
		if downgrade.Load() {
			sig = "v1:untrusted"
		}
		_ = json.NewEncoder(w).Encode(contracts.HeartbeatV2Response{Command: &contracts.SignedRemoteCommand{Payload: command, Signature: sig}})
	}))
	defer s.Close()
	c := &Client{Options: Options{Origin: s.URL, EnrollmentToken: "synthetic", PolicyPublicKey: private.Public().(ed25519.PublicKey)}, HTTP: s.Client()}
	if _, _, err := c.Policy(context.Background(), command.DeviceID, "synthetic"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Heartbeat(context.Background(), contracts.HeartbeatV2Request{}, "synthetic"); err != nil {
		t.Fatal(err)
	}
	downgrade.Store(true)
	if _, _, err := c.Policy(context.Background(), command.DeviceID, "synthetic"); err == nil {
		t.Fatal("accepted HMAC downgrade")
	}
	if _, err := c.Heartbeat(context.Background(), contracts.HeartbeatV2Request{}, "synthetic"); err == nil {
		t.Fatal("accepted legacy command")
	}
}

func TestPublicKeyConfigurationIsExclusive(t *testing.T) {
	base := Options{Origin: "http://127.0.0.1:8080", EnrollmentToken: "synthetic", TransportKey: make([]byte, 32), TransportKeyID: "test"}
	base.PolicyPublicKey = make([]byte, 32)
	if _, err := New(base); err != nil {
		t.Fatal(err)
	}
	base.PolicyKey = make([]byte, 32)
	if _, err := New(base); err == nil {
		t.Fatal("accepted ambiguous policy keys")
	}
	base.PolicyKey = nil
	base.PolicyPublicKey = make([]byte, 31)
	if _, err := New(base); err == nil {
		t.Fatal("accepted invalid public key")
	}
}

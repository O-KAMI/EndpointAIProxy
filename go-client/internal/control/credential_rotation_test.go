package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"endpointai/client/internal/contracts"
	"endpointai/client/internal/protect"
	"endpointai/client/internal/protocol"
	"endpointai/client/internal/state"
)

type rotationNoNetwork struct{ calls int }

func (n *rotationNoNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	n.calls++
	return nil, errors.New("unexpected synthetic network call")
}

func rotationValidationFixture(t *testing.T) (*Client, *state.Store, *rotationNoNetwork, string, string) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	p, err := protect.NewFileKey(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := state.Open(filepath.Join(dir, "state.db"), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	key := bytes.Repeat([]byte{7}, 32)
	c, err := New(Options{Origin: "https://127.0.0.1:1", CertificatePin: base64.StdEncoding.EncodeToString(key), EnrollmentToken: "synthetic", PolicyKey: key, TransportKey: key, TransportKeyID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	device := "11111111-2222-4333-8444-555555555555"
	token := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	hash := sha256.Sum256([]byte(token))
	binding := persistedDeviceTransport{Origin: c.Options.Origin, Pin: c.Options.CertificatePin, Device: device, KeyID: "dv2_1_11111111222243338444555555555555", Key: key, TokenHash: hash[:]}
	data, _ := json.Marshal(binding)
	if err = s.SaveDeviceTransport(ctx, string(data)); err != nil {
		t.Fatal(err)
	}
	if err = c.AttachDeviceTransportStore(ctx, s); err != nil {
		t.Fatal(err)
	}
	network := &rotationNoNetwork{}
	c.HTTP.Transport.(*protocol.Transport).Base = network
	return c, s, network, device, token
}

func TestRotationRejectsChangedPendingIdentityBeforeNetwork(t *testing.T) {
	for _, field := range []string{"json", "origin", "pin", "device", "old-hash", "token", "rotation-id", "binding-device", "binding-hash", "binding-key"} {
		t.Run(field, func(t *testing.T) {
			c, s, network, device, token := rotationValidationFixture(t)
			oldHash := sha256.Sum256([]byte(token))
			next := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
			nextHash := sha256.Sum256([]byte(next))
			work := pendingCredentialRotation{Device: device, Origin: c.Options.Origin, Pin: c.Options.CertificatePin, RotationID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", Token: next, PreviousHash: oldHash[:]}
			work.Binding = &persistedDeviceTransport{Origin: work.Origin, Pin: work.Pin, Device: device, KeyID: "dv2_1_11111111222243338444555555555555", Key: bytes.Repeat([]byte{4}, 32), TokenHash: nextHash[:]}
			switch field {
			case "origin":
				work.Origin = "https://other.invalid/"
			case "pin":
				work.Pin = "other"
			case "device":
				work.Device = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
			case "old-hash":
				work.PreviousHash = make([]byte, 32)
			case "token":
				work.Token = "invalid"
			case "rotation-id":
				work.RotationID = "00000000-0000-0000-0000-000000000000"
			case "binding-device":
				work.Binding.Device = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
			case "binding-hash":
				work.Binding.TokenHash = make([]byte, 32)
			case "binding-key":
				work.Binding.Key = make([]byte, 31)
			}
			data, _ := json.Marshal(work)
			if field == "json" {
				data = []byte("invalid")
			}
			if err := s.SavePendingCredentialRotation(context.Background(), "", string(data)); err != nil {
				t.Fatal(err)
			}
			changed, pending, err := c.RotateCredential(context.Background(), device, token, time.Now().Add(-31*24*time.Hour), nil)
			if err == nil || changed || !pending || network.calls != 0 {
				t.Fatal("invalid pending state escaped to network", err)
			}
		})
	}
}

func TestRotationUsesServerAgeAndNegotiation(t *testing.T) {
	for _, mode := range []string{"unsupported", "not-due", "short-age", "zero-server-time"} {
		t.Run(mode, func(t *testing.T) {
			c, s, network, device, token := rotationValidationFixture(t)
			now := time.Now().UTC()
			reply := &contracts.HeartbeatV2Response{ServerTimeUTC: now, CredentialRotationV1: &contracts.CredentialRotationCapability{MinAgeSeconds: 30 * 86400}}
			enrolled := now.Add(-31 * 24 * time.Hour)
			switch mode {
			case "unsupported":
				reply.CredentialRotationV1 = nil
			case "not-due":
				enrolled = now.Add(-time.Hour)
			case "short-age":
				reply.CredentialRotationV1.MinAgeSeconds = 1
			case "zero-server-time":
				reply.ServerTimeUTC = time.Time{}
			}
			changed, pending, err := c.RotateCredential(context.Background(), device, token, enrolled, reply)
			wantError := mode == "short-age" || mode == "zero-server-time"
			if (err != nil) != wantError || changed || pending || network.calls != 0 {
				t.Fatal("invalid age/capability handling", err)
			}
			if value, err := s.LoadPendingCredentialRotation(context.Background()); err != nil || value != "" {
				t.Fatal("unscheduled credential created", err)
			}
		})
	}
}

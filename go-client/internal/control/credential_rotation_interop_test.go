package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"endpointai/client/internal/contracts"
	"endpointai/client/internal/protect"
	"endpointai/client/internal/protocol"
	"endpointai/client/internal/state"
)

type dropRotationResponse struct {
	base      http.RoundTripper
	at, count int
}

func (d *dropRotationResponse) RoundTrip(r *http.Request) (*http.Response, error) {
	d.count++
	response, err := d.base.RoundTrip(r)
	if err == nil && d.count == d.at {
		response.Body.Close()
		return nil, errors.New("synthetic response loss")
	}
	return response, err
}

type failRotationCommitOnce struct {
	*state.Store
	failed bool
}

func (s *failRotationCommitOnce) CommitCredentialRotation(ctx context.Context, v contracts.CredentialRotationState) error {
	if !s.failed {
		s.failed = true
		return errors.New("synthetic local commit failure")
	}
	return s.Store.CommitCredentialRotation(ctx, v)
}

// Executed only by the isolated Python/MySQL fixture over pinned loopback TLS.
func TestCredentialRotationPythonInterop(t *testing.T) {
	origin := os.Getenv("ENDPOINTAI_ROTATION_TEST_ORIGIN")
	if origin == "" {
		t.Skip("synthetic rotation server not configured")
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		t.Fatal("loopback HTTPS required")
	}
	device, mode := os.Getenv("ENDPOINTAI_ROTATION_TEST_DEVICE"), os.Getenv("ENDPOINTAI_ROTATION_TEST_MODE")
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "server", "tests", "fixtures", "dotnet-v0.1.19.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Heartbeat contracts.HeartbeatV2Request `json:"heartbeat"`
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	fixture.Heartbeat.Device.DeviceID = device
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	opts := Options{Origin: origin, CertificatePin: os.Getenv("ENDPOINTAI_ROTATION_TEST_PIN"), EnrollmentToken: "test-enrollment-token", PolicyKey: key, TransportKey: key, TransportKeyID: "production-2026-01"}
	dir := t.TempDir()
	p, err := protect.NewFileKey(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	store, err := state.Open(path, p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { store.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	newClient := func() *Client {
		t.Helper()
		c, err := New(opts)
		if err != nil {
			t.Fatal(err)
		}
		if err = c.AttachDeviceTransportStore(ctx, store); err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := newClient()
	oldToken := base64.StdEncoding.EncodeToString([]byte("oooooooooooooooooooooooooooooooo"))
	originBinding, pin := c.Options.Origin, c.Options.CertificatePin
	old := state.Credential{Token: oldToken, EnrolledAtUTC: time.Now().UTC().Add(-31 * 24 * time.Hour), ServerOrigin: &originBinding, ServerCertificateSPKISHA256: &pin}
	if err = store.SaveCredential(ctx, old); err != nil {
		t.Fatal(err)
	}
	if mode == "local-commit-failure" {
		if err = c.AttachDeviceTransportStore(ctx, &failRotationCommitOnce{Store: store}); err != nil {
			t.Fatal(err)
		}
	}
	transport := c.HTTP.Transport.(*protocol.Transport)
	if mode == "prepare-loss-disable" {
		transport.Base = &dropRotationResponse{base: transport.Base, at: 2}
	}
	if mode == "commit-loss-expired-grace" {
		transport.Base = &dropRotationResponse{base: transport.Base, at: 3}
	}
	reply, err := c.Heartbeat(ctx, fixture.Heartbeat, old.Token)
	if err != nil || reply.CredentialRotationV1 == nil {
		t.Fatal("negotiation failed", err)
	}
	oldClient := newClient()
	changed, pending, err := c.RotateCredential(ctx, device, old.Token, old.EnrolledAtUTC, &reply)
	if mode == "revoked" {
		if err == nil || changed || !pending {
			t.Fatal("revoked credential activated")
		}
		got, err := store.LoadCredential(ctx)
		if err != nil || got.Token != old.Token {
			t.Fatal("revoked credential changed locally")
		}
		value, err := store.LoadPendingCredentialRotation(ctx)
		if err != nil || value == "" {
			t.Fatal("pending evidence lost")
		}
		return
	}
	wantFailure := mode == "prepare-loss-disable" || mode == "commit-loss-expired-grace" || mode == "local-commit-failure"
	if wantFailure {
		if err == nil || changed || !pending {
			t.Fatal("failure not preserved", err)
		}
		got, loadErr := store.LoadCredential(ctx)
		if loadErr != nil || got.Token != old.Token {
			t.Fatal("failed flow replaced old credential", loadErr)
		}
		if err = store.Close(); err != nil {
			t.Fatal(err)
		}
		store, err = state.Open(path, p)
		if err != nil {
			t.Fatal(err)
		}
		c = newClient()
		changed, pending, err = c.RotateCredential(ctx, device, old.Token, old.EnrolledAtUTC, nil)
	}
	if err != nil || !changed || pending {
		t.Fatal("rotation did not finish", err)
	}
	got, err := store.LoadCredential(ctx)
	if err != nil || got.Token == old.Token || !validRotationToken(got.Token) {
		t.Fatal("new credential missing", err)
	}
	if value, err := store.LoadPendingCredentialRotation(ctx); err != nil || value != "" {
		t.Fatal("pending not cleared", err)
	}
	if _, _, err = c.Policy(ctx, device, got.Token); err != nil {
		t.Fatal("new token/binding rejected", err)
	}
	_, _, err = oldClient.Policy(ctx, device, old.Token)
	expired := mode == "commit-loss-expired-grace" || mode == "local-commit-failure"
	if (err != nil) != expired {
		t.Fatal("unexpected old-token overlap result", err)
	}
	c = newClient()
	if _, _, err = c.Policy(ctx, device, got.Token); err != nil {
		t.Fatal("new token/binding lost after reload", err)
	}
	changed, pending, err = c.RotateCredential(ctx, device, got.Token, got.EnrolledAtUTC, nil)
	if err != nil || changed || pending {
		t.Fatal("completed rotation resumed again", err)
	}
}

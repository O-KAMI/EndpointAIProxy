package app

import (
	"context"
	"endpointai/client/internal/audit"
	"endpointai/client/internal/control"
	"endpointai/client/internal/platform"
	"endpointai/client/internal/protect"
	"endpointai/client/internal/state"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// This test only connects to the synthetic loopback server started by pytest.
func TestInitialEnrollmentLostResponsePythonInterop(t *testing.T) {
	origin := os.Getenv("ENDPOINTAI_SYNTHETIC_INTEROP_ORIGIN")
	if origin == "" {
		t.Skip("synthetic interop server not configured")
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		t.Fatal("synthetic loopback origin required")
	}
	dir := t.TempDir()
	ctx := context.Background()
	protector, err := protect.NewFileKey(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "state.db")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	opts := control.Options{Origin: origin, EnrollmentToken: "test-enrollment-token", PolicyKey: key, TransportKey: key, TransportKeyID: "production-2026-01"}
	profiles := func(context.Context) ([]platform.Profile, error) { return []platform.Profile{}, nil }
	makeApp := func(store *state.Store) *App {
		a, err := New(ctx, Options{Version: "synthetic", Listen: "127.0.0.1:18080", DataRoot: dir, Policy: testPolicy(1), Control: &opts}, store, audit.New(filepath.Join(dir, "logs")), profiles)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	store, err := state.Open(dbPath, protector)
	if err != nil {
		t.Fatal(err)
	}
	a := makeApp(store)
	a.Client.HTTP.Transport = &dropEnrollmentResponse{base: a.Client.HTTP.Transport}
	if _, err = a.enroll(ctx); err == nil {
		t.Fatal("first response was not lost")
	}
	if credential, err := store.LoadCredential(ctx); err != nil || credential != nil {
		t.Fatal("unexpected saved credential")
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = state.Open(dbPath, protector)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	resumed := makeApp(store)
	credential, err := resumed.enroll(ctx)
	if err != nil {
		t.Fatalf("retry failed: %v", err)
	}
	if _, _, err = resumed.Client.Policy(ctx, resumed.DeviceID(), credential.Token); err != nil {
		t.Fatalf("retried credential rejected: %v", err)
	}
	if pending, err := store.LoadPendingEnrollment(ctx); err != nil || pending != "" {
		t.Fatal("pending state not cleared")
	}
}

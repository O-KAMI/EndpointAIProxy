package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"endpointai/client/internal/audit"
	"endpointai/client/internal/platform"
	"endpointai/client/internal/protect"
	"endpointai/client/internal/state"
)

func TestPublicKeyCacheMigrationOfflineAndTamper(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	protector, err := protect.NewFileKey(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(filepath.Join(dir, "state.db"), protector)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	policy := testPolicy(2)
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	message := append([]byte("sf-endpointai-policy-ed25519-v1\n"), raw...)
	signature := "ed25519-v1:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))
	// A legacy cached policy remains usable offline while the new mode is rolled out.
	if err := store.SavePolicy(ctx, policy, "v1:legacy-fixture", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	control := newFakeControl(t).options()
	control.PolicyKey = nil
	control.PolicyPublicKey = private.Public().(ed25519.PublicKey)
	opts := Options{Version: "test", Listen: "127.0.0.1:18080", DataRoot: dir, Policy: testPolicy(1), Control: &control}
	open := func() *App {
		a, err := New(ctx, opts, store, audit.New(filepath.Join(dir, "logs")), func(context.Context) ([]platform.Profile, error) { return nil, nil })
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	a := open()
	if a.Policy().PolicyVersion != 2 {
		t.Fatal("legacy offline cache lost")
	}
	if err := a.ApplyPolicy(ctx, policy, signature, raw); err != nil {
		t.Fatal(err)
	}
	cached, err := store.LoadPolicy(ctx)
	if err != nil || cached.Signature != signature || string(cached.RawPolicy) != string(raw) {
		t.Fatal("signed cache was not upgraded", err)
	}
	if got := open().Policy().PolicyVersion; got != 2 {
		t.Fatalf("verified cache lost: %d", got)
	}
	modified := policy
	modified.Enabled = !modified.Enabled
	if err := store.SavePolicy(ctx, modified, signature, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if got := open().Policy().PolicyVersion; got != 1 {
		t.Fatalf("tampered cache accepted: %d", got)
	}
}

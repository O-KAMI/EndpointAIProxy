package state

import (
	"context"
	"endpointai/client/internal/protect"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestStateFingerprintIsReadOnlyLogicalAndValidatesSecrets(t *testing.T) {
	dir := t.TempDir()
	key, e := protect.NewFileKey(filepath.Join(dir, "key"))
	if e != nil {
		t.Fatal(e)
	}
	s, e := Open(filepath.Join(dir, "state.db"), key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := context.Background()
	if id, e := s.ReadDeviceID(ctx); e != nil || id != "" {
		t.Fatal("missing identity was changed", e)
	}
	empty, e := s.StateFingerprint(ctx)
	if e != nil || len(empty) != 6 {
		t.Fatal(empty, e)
	}
	if id, e := s.ReadDeviceID(ctx); e != nil || id != "" {
		t.Fatal("fingerprint created identity", e)
	}
	id, e := s.GetOrCreateDeviceID(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := s.ReadDeviceID(ctx); e != nil || got != id {
		t.Fatal("existing identity not preserved", e)
	}
	r := routeFixture()
	if e = s.UpsertRoute(ctx, r); e != nil {
		t.Fatal(e)
	}
	credential := Credential{Token: "synthetic-secret-token", EnrolledAtUTC: time.Now().UTC()}
	if e = s.SaveCredential(ctx, credential); e != nil {
		t.Fatal(e)
	}
	before, e := s.StateFingerprint(ctx)
	if e != nil {
		t.Fatal(e)
	}
	// AEAD re-encryption changes ciphertext, not logical compatibility.
	if e = s.UpsertRoute(ctx, r); e != nil {
		t.Fatal(e)
	}
	if e = s.SaveCredential(ctx, credential); e != nil {
		t.Fatal(e)
	}
	after, e := s.StateFingerprint(ctx)
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("randomized protection changed logical fingerprint", e)
	}
	for _, value := range after {
		if len(value) != 64 || strings.Contains(value, "synthetic") {
			t.Fatal("fingerprint exposed state")
		}
	}
	backup := filepath.Join(dir, "backup.db")
	if e = s.Backup(ctx, backup); e != nil {
		t.Fatal(e)
	}
	ro, e := OpenReadOnly(backup, key)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	restored, e := ro.StateFingerprint(ctx)
	if e != nil || !reflect.DeepEqual(after, restored) {
		t.Fatal("backup/read-only compatibility fingerprint differed", e)
	}
	if after["identity"] == empty["identity"] || after["routes"] == empty["routes"] || after["credential"] == empty["credential"] {
		t.Fatal("state components not covered")
	}
	if _, e = s.db.Exec("UPDATE device_credential SET protected_token=?", []byte("corrupt-fixture")); e != nil {
		t.Fatal(e)
	}
	if _, e = s.StateFingerprint(ctx); e == nil {
		t.Fatal("fingerprint accepted undecryptable credential")
	}
}

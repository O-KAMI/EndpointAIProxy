package state

import (
	"bytes"
	"context"
	"endpointai/client/internal/contracts"
	"endpointai/client/internal/protect"
	"path/filepath"
	"testing"
	"time"
)

func TestCredentialRotationAtomicRestartAndCompareAndSwap(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	p, err := protect.NewFileKey(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	s, err := Open(path, p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	origin, pin := "https://synthetic.invalid/", "synthetic-pin"
	old := Credential{Token: "synthetic-old-token", EnrolledAtUTC: time.Now().Add(-31 * 24 * time.Hour).UTC(), ServerOrigin: &origin, ServerCertificateSPKISHA256: &pin}
	if err = s.SaveCredential(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveDeviceTransport(ctx, "synthetic-old-binding"); err != nil {
		t.Fatal(err)
	}
	if err = s.SavePendingCredentialRotation(ctx, "", "synthetic-pending"); err != nil {
		t.Fatal(err)
	}
	if err = s.SavePendingCredentialRotation(ctx, "", "overwrite"); err == nil {
		t.Fatal("pending work overwritten")
	}
	if err = s.SavePendingCredentialRotation(ctx, "wrong", "overwrite"); err == nil {
		t.Fatal("changed state accepted")
	}
	v := contracts.CredentialRotationState{PreviousToken: old.Token, Pending: "synthetic-pending", Token: "synthetic-new-token", Transport: "synthetic-new-binding", Origin: origin, Pin: pin, ActivatedAtUTC: time.Now().UTC()}
	assertOld := func() {
		t.Helper()
		got, err := s.LoadCredential(ctx)
		if err != nil || got.Token != old.Token {
			t.Fatal("credential changed after failed commit", err)
		}
		binding, err := s.LoadDeviceTransport(ctx)
		if err != nil || binding != "synthetic-old-binding" {
			t.Fatal("binding changed after failed commit", err)
		}
		pending, err := s.LoadPendingCredentialRotation(ctx)
		if err != nil || pending != v.Pending {
			t.Fatal("pending lost after failed commit", err)
		}
	}
	for _, field := range []string{"token", "pending", "origin", "pin"} {
		bad := v
		switch field {
		case "token":
			bad.PreviousToken = "different"
		case "pending":
			bad.Pending = "different"
		case "origin":
			bad.Origin = "https://other.invalid/"
		case "pin":
			bad.Pin = "other"
		}
		if err = s.CommitCredentialRotation(ctx, bad); err == nil {
			t.Fatal("CAS mismatch accepted", field)
		}
		assertOld()
	}
	// Fail after both the token and binding writes, while clearing pending work.
	_, err = s.db.Exec(`CREATE TRIGGER fail_rotation BEFORE DELETE ON pending_credential_rotation BEGIN SELECT RAISE(ABORT,'synthetic'); END`)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CommitCredentialRotation(ctx, v); err == nil {
		t.Fatal("transaction failure accepted")
	}
	assertOld()
	if err = s.RecoverCredential(ctx, Credential{Token: v.Token, EnrolledAtUTC: v.ActivatedAtUTC, ServerOrigin: &origin, ServerCertificateSPKISHA256: &pin}); err == nil {
		t.Fatal("recovery transaction failure accepted")
	}
	assertOld()
	if _, err = s.db.Exec("DROP TRIGGER fail_rotation"); err != nil {
		t.Fatal(err)
	}
	if err = s.CommitCredentialRotation(ctx, v); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadCredential(ctx)
	if err != nil || got.Token != v.Token || !got.EnrolledAtUTC.Equal(v.ActivatedAtUTC) {
		t.Fatal("committed credential lost", err)
	}
	binding, err := s.LoadDeviceTransport(ctx)
	if err != nil || binding != v.Transport {
		t.Fatal("committed binding lost", err)
	}
	pending, err := s.LoadPendingCredentialRotation(ctx)
	if err != nil || pending != "" {
		t.Fatal("pending not cleared", err)
	}
	var tokenData, bindingData []byte
	if err = s.db.QueryRow("SELECT protected_token FROM device_credential").Scan(&tokenData); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow("SELECT protected_state FROM device_transport_state").Scan(&bindingData); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(tokenData, []byte(v.Token)) || bytes.Contains(bindingData, []byte(v.Transport)) {
		t.Fatal("secret stored in plaintext")
	}
}

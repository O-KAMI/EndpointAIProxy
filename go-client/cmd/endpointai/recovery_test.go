package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"endpointai/client/internal/control"
	"endpointai/client/internal/protect"
	"endpointai/client/internal/state"
)

func TestCredentialRecoveryChecksIdentityAndServerBeforeReplacing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	p, err := protect.NewFileKey(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(filepath.Join(dir, "state.db"), p)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	device, err := store.GetOrCreateDeviceID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	old := state.Credential{Token: "old-token", EnrolledAtUTC: time.Now()}
	if err := store.SaveCredential(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveDeviceTransport(ctx, "synthetic-old-binding"); err != nil {
		t.Fatal(err)
	}
	if err := store.SavePendingCredentialRotation(ctx, "", "synthetic-pending"); err != nil {
		t.Fatal(err)
	}
	token := base64.StdEncoding.EncodeToString(make([]byte, 32))
	encode := func(id string) string {
		b, _ := json.Marshal(map[string]any{"deviceId": id, "deviceToken": token, "enrolledAtUtc": time.Now().UTC()})
		return string(b)
	}
	opts := control.Options{Origin: "http://127.0.0.1:8080/", CertificatePin: "fixture"}
	verified := 0
	verify := func(id, supplied string) error {
		verified++
		if id != device || supplied != token {
			t.Fatal("wrong verification input")
		}
		return nil
	}
	if err := recoverCredential(ctx, store, opts, strings.NewReader(encode("wrong")), verify); err == nil || verified != 0 {
		t.Fatal("mismatched device accepted")
	}
	if err := recoverCredential(ctx, store, opts, strings.NewReader(encode(device)), func(string, string) error { return errors.New("unavailable") }); err == nil {
		t.Fatal("unverified token accepted")
	}
	previous, _ := store.LoadCredential(ctx)
	if previous.Token != old.Token {
		t.Fatal("failed recovery changed existing token")
	}
	if binding, err := store.LoadDeviceTransport(ctx); err != nil || binding != "synthetic-old-binding" {
		t.Fatal("failed recovery changed binding", err)
	}
	if pending, err := store.LoadPendingCredentialRotation(ctx); err != nil || pending != "synthetic-pending" {
		t.Fatal("failed recovery cleared pending", err)
	}
	if err := recoverCredential(ctx, store, opts, strings.NewReader(encode(device)), verify); err != nil {
		t.Fatal(err)
	}
	updated, err := store.LoadCredential(ctx)
	if err != nil || updated.Token != token || *updated.ServerOrigin != opts.Origin || *updated.ServerCertificateSPKISHA256 != opts.CertificatePin {
		t.Fatal("verified credential was not stored with server binding", err)
	}
	if binding, err := store.LoadDeviceTransport(ctx); err != nil || binding != "" {
		t.Fatal("recovery retained old binding", err)
	}
	if pending, err := store.LoadPendingCredentialRotation(ctx); err != nil || pending != "" {
		t.Fatal("recovery retained pending rotation", err)
	}
}

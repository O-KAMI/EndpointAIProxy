package state

import (
	"bytes"
	"context"
	"database/sql"
	"endpointai/client/internal/contracts"
	"endpointai/client/internal/protect"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPendingEventsSurviveRestartAndRemainBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	p, err := protect.NewFileKey(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, p)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < 1001; i++ {
		event := contracts.EndpointEvent{EventID: fmt.Sprintf("synthetic-%04d", i), OccurredAtUTC: time.Now().UTC(), Severity: contracts.EventSeverityWarning, Type: "client", Code: "TEST", Summary: "Synthetic event"}
		dropped, err := s.EnqueueEvent(ctx, event)
		if err != nil || dropped != int64(i/1000) {
			t.Fatalf("enqueue %d dropped=%d: %v", i, dropped, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	events, err := s.PendingEvents(ctx)
	if err != nil || len(events) != 1000 || events[0].EventID != "synthetic-0001" {
		t.Fatalf("pending after restart: %d, %v", len(events), err)
	}
	if err := s.DeletePendingEvents(ctx, events[:2]); err != nil {
		t.Fatal(err)
	}
	events, err = s.PendingEvents(ctx)
	if err != nil || len(events) != 998 || events[0].EventID != "synthetic-0003" {
		t.Fatalf("pending after acknowledgement: %d, %v", len(events), err)
	}
}

func TestLegacySchemaAndStateCompatibility(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	_, e = db.Exec(`CREATE TABLE device_credential(singleton_id INTEGER PRIMARY KEY,protected_token BLOB NOT NULL,enrolled_at_utc TEXT NOT NULL);CREATE TABLE remote_command_receipts(command_id TEXT PRIMARY KEY,command_type INTEGER NOT NULL,status INTEGER NOT NULL,received_at_utc TEXT NOT NULL,completed_at_utc TEXT NULL,result_code TEXT NULL,result_summary TEXT NULL);CREATE TABLE client_identity(singleton_id INTEGER PRIMARY KEY,device_id TEXT NOT NULL,created_at_utc TEXT NOT NULL);INSERT INTO client_identity VALUES(1,'10000000-0000-0000-0000-000000000001','2026-09-13T00:00:00.1234567+00:00');`)
	if e != nil {
		t.Fatal(e)
	}
	db.Close()
	p, e := protect.NewFileKey(filepath.Join(dir, "key"))
	if e != nil {
		t.Fatal(e)
	}
	s, e := Open(path, p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := context.Background()
	id, e := s.GetOrCreateDeviceID(ctx)
	if e != nil || id != "10000000-0000-0000-0000-000000000001" {
		t.Fatalf("%s %v", id, e)
	}
	now := time.Now().UTC().Truncate(100 * time.Nanosecond)
	r := contracts.Route{RouteID: "legacy", UserSID: "synthetic-user", AgentType: 8, ProviderID: "default", OriginalBaseURL: "https://example.invalid/v1", InjectedBaseURL: "http://127.0.0.1:18080/r/legacy", Status: 3, CreatedAtUTC: now, UpdatedAtUTC: now}
	if e = s.UpsertRoute(ctx, r); e != nil {
		t.Fatal(e)
	}
	found, e := s.FindRoute(ctx, r.RouteID)
	if e != nil || found.OriginalBaseURL != r.OriginalBaseURL || !found.CreatedAtUTC.Equal(now) {
		t.Fatalf("%+v %v", found, e)
	}
	if e = s.SaveCredential(ctx, Credential{Token: "synthetic-token", EnrolledAtUTC: now}); e != nil {
		t.Fatal(e)
	}
	v, e := s.LoadCredential(ctx)
	if e != nil || v.Token != "synthetic-token" {
		t.Fatalf("%+v %v", v, e)
	}
	op := OperationState{State: contracts.ClientOperationStateDisabled, UpdatedAtUTC: now}
	if e = s.SaveOperationState(ctx, op); e != nil {
		t.Fatal(e)
	}
	got, e := s.LoadOperationState(ctx)
	if e != nil || got.State != op.State {
		t.Fatalf("%+v %v", got, e)
	}
	receipt := CommandReceipt{CommandID: "30000000-0000-0000-0000-000000000003", Type: contracts.RemoteCommandTypeDisableProxy, Status: contracts.RemoteCommandStatusExecuting, ReceivedAtUTC: now, DeviceID: &id, IssuedAtUTC: &now}
	if e = s.SaveCommandReceipt(ctx, receipt); e != nil {
		t.Fatal(e)
	}
	list, e := s.ListExecutingReceipts(ctx, id)
	if e != nil || len(list) != 1 {
		t.Fatalf("%+v %v", list, e)
	}
	receipt.DeviceID = nil
	receipt.IssuedAtUTC = nil
	receipt.Status = contracts.RemoteCommandStatusSucceeded
	if e = s.SaveCommandReceipt(ctx, receipt); e != nil {
		t.Fatal(e)
	}
	saved, e := s.LoadCommandReceipt(ctx, receipt.CommandID)
	if e != nil || saved.DeviceID == nil || saved.IssuedAtUTC == nil {
		t.Fatalf("%+v %v", saved, e)
	}
	// Database stores encrypted fields, never the clear token/original URI.
	var raw []byte
	if e = s.db.QueryRow("SELECT protected_token FROM device_credential").Scan(&raw); e != nil {
		t.Fatal(e)
	}
	if string(raw) == "synthetic-token" {
		t.Fatal("plaintext credential")
	}
	if e = s.DeleteRoute(ctx, r.RouteID); e != nil {
		t.Fatal(e)
	}
	if got, e := s.FindRoute(ctx, r.RouteID); e != nil || got != nil {
		t.Fatalf("%+v %v", got, e)
	}
}

func TestStateRejectsUnprotectedAndSymlinkDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	if s, e := Open(path, nil); e == nil {
		s.Close()
		t.Fatal("accepted missing protector")
	}
	p, e := protect.NewFileKey(filepath.Join(dir, "key"))
	if e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(dir, "target")
	if e = os.WriteFile(target, []byte{}, 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(target, path); e != nil {
		t.Skip(e)
	}
	if s, e := Open(path, p); e == nil {
		s.Close()
		t.Fatal("accepted symlink database")
	}
}

func TestOnlineBackupAndReadOnly(t *testing.T) {
	dir := t.TempDir()
	p, e := protect.NewFileKey(filepath.Join(dir, "key"))
	if e != nil {
		t.Fatal(e)
	}
	s, e := Open(filepath.Join(dir, "状态 #.db"), p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := context.Background()
	id, e := s.GetOrCreateDeviceID(ctx)
	if e != nil {
		t.Fatal(e)
	}
	backup := filepath.Join(dir, "备份 #.db")
	if e = s.Backup(ctx, backup); e != nil {
		t.Fatal(e)
	}
	ro, e := OpenReadOnly(backup, p)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	var copied string
	if e = ro.db.QueryRow("SELECT device_id FROM client_identity").Scan(&copied); e != nil || copied != id {
		t.Fatalf("%s %v", copied, e)
	}
	if _, e = ro.GetOrCreateDeviceID(ctx); e == nil {
		t.Fatal("read-only store accepted write")
	}
	if e = s.Backup(ctx, backup); e == nil {
		t.Fatal("backup overwrote existing destination")
	}
	missing := filepath.Join(dir, "missing.db")
	if v, e := OpenReadOnly(missing, p); e == nil {
		v.Close()
		t.Fatal("created missing database")
	}
	if _, e = os.Stat(missing); !os.IsNotExist(e) {
		t.Fatalf("missing database created: %v", e)
	}
}

func TestDeviceTransportStateIsProtectedAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	protector, err := protect.NewFileKey(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, protector)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const secret = `{"syntheticKey":"sensitive-device-key"}`
	if err = s.SaveDeviceTransport(ctx, secret); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err = s.db.QueryRowContext(ctx, "SELECT protected_state FROM device_transport_state").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("sensitive-device-key")) {
		t.Fatal("stored state is not protected")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, protector)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.LoadDeviceTransport(ctx)
	if err != nil || got != secret {
		t.Fatalf("state not restored: %v", err)
	}
}

func TestEnrollmentCredentialAndPendingStateCommitTogether(t *testing.T) {
	dir := t.TempDir()
	protector, err := protect.NewFileKey(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(dir, "state.db"), protector)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	const pending = `{"token":"synthetic-pending-secret"}`
	if err = store.SavePendingEnrollment(ctx, pending); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err = store.db.QueryRowContext(ctx, "SELECT protected_state FROM pending_device_enrollment").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("synthetic-pending-secret")) {
		t.Fatal("pending token stored in clear")
	}
	if _, err = store.db.Exec(`CREATE TRIGGER reject_pending_delete BEFORE DELETE ON pending_device_enrollment BEGIN SELECT RAISE(ABORT, 'synthetic'); END`); err != nil {
		t.Fatal(err)
	}
	credential := Credential{Token: "synthetic-device-token", EnrolledAtUTC: time.Now().UTC()}
	if err = store.CommitEnrollment(ctx, credential); err == nil {
		t.Fatal("failed deletion committed credential")
	}
	if got, err := store.LoadCredential(ctx); err != nil || got != nil {
		t.Fatal("credential transaction was not rolled back")
	}
	if got, err := store.LoadPendingEnrollment(ctx); err != nil || got != pending {
		t.Fatal("pending enrollment was lost")
	}
	if _, err = store.db.Exec("DROP TRIGGER reject_pending_delete"); err != nil {
		t.Fatal(err)
	}
	if err = store.CommitEnrollment(ctx, credential); err != nil {
		t.Fatal(err)
	}
	if got, err := store.LoadPendingEnrollment(ctx); err != nil || got != "" {
		t.Fatal("pending enrollment remains")
	}
	if got, err := store.LoadCredential(ctx); err != nil || got == nil || got.Token != credential.Token {
		t.Fatal("credential missing")
	}
}

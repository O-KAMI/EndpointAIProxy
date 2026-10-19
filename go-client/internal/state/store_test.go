package state

import (
	"context"
	"database/sql"
	"endpointai/client/internal/contracts"
	"endpointai/client/internal/protect"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
	s, e := Open(filepath.Join(dir, "state.db"), p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := context.Background()
	id, e := s.GetOrCreateDeviceID(ctx)
	if e != nil {
		t.Fatal(e)
	}
	backup := filepath.Join(dir, "backup.db")
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

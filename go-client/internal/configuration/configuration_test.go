package configuration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClaudePreservesCredentialsAndUnrelatedFields(t *testing.T) {
	input := []byte(`{"env":{"ANTHROPIC_AUTH_TOKEN":"fixture-only","OTHER":"保留"},"permissions":{"allow":["Read"]}}`)
	got, e := Claude(input, "http://127.0.0.1:18080/r/test", false)
	if e != nil {
		t.Fatal(e)
	}
	var obj map[string]any
	if e = json.Unmarshal(got.Content, &obj); e != nil {
		t.Fatal(e)
	}
	env := obj["env"].(map[string]any)
	if env["OTHER"] != "保留" || env["ANTHROPIC_AUTH_TOKEN"] != "fixture-only" || obj["permissions"] == nil {
		t.Fatal("unrelated fields lost")
	}
	again, e := Claude(got.Content, got.Injected, false)
	if e != nil || again.Changed || !bytes.Equal(again.Content, got.Content) {
		t.Fatal("not idempotent")
	}
	for _, bad := range []string{`[]`, `{"env":[]}`, `{"env":{"ANTHROPIC_BASE_URL":17}}`} {
		if _, e := Claude([]byte(bad), got.Injected, false); e == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	if _, e := Claude(input, "https://remote.example/v1", false); e == nil {
		t.Fatal("remote injection accepted")
	}
}
func TestCodexChangesOnlyActiveProviderAndPreservesComments(t *testing.T) {
	input := []byte("model_provider = \"custom\"\r\nmodel = \"model\"\r\n[model_providers.custom]\r\n  base_url = \"https://upstream.example/v1\" # preserve\r\napi_key = \"fixture\"\r\n[model_providers.other]\r\nbase_url = \"https://other.example\"\r\n")
	got, e := Codex(input, "http://127.0.0.1:18080/r/test", false)
	if e != nil {
		t.Fatal(e)
	}
	expected := bytes.Replace(input, []byte("https://upstream.example/v1"), []byte(got.Injected), 1)
	if !bytes.Equal(expected, got.Content) {
		t.Fatalf("unexpected mutation %s", got.Content)
	}
	if _, e = Codex([]byte("model_provider = \"missing\"\n"), got.Injected, false); e == nil {
		t.Fatal("missing provider accepted")
	}
	got, e = Codex([]byte("model = \"x\"\n[features]\nx = true\n"), got.Injected, false)
	if e != nil || got.Previous != "https://api.openai.com/v1" || !strings.Contains(string(got.Content), "openai_base_url =") {
		t.Fatal(got, e)
	}
}
func TestAtomicBackupConcurrentChangeAndRollback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	backup := filepath.Join(dir, "backups")
	if e := os.WriteFile(path, []byte("before"), 0640); e != nil {
		t.Fatal(e)
	}
	if _, e := ApplyFile(context.Background(), path, []byte("stale"), []byte("after"), backup); e == nil {
		t.Fatal("stale write accepted")
	}
	u, e := ApplyFile(context.Background(), path, []byte("before"), []byte("after"), backup)
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(u.Backup)
	if e != nil || string(b) != "before" {
		t.Fatal("backup mismatch", e)
	}
	if e = os.WriteFile(path, []byte("user change"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = u.Rollback(context.Background(), backup); e == nil {
		t.Fatal("overwrote user change")
	}
	b, _ = os.ReadFile(path)
	if string(b) != "user change" {
		t.Fatal("user change lost")
	}
}
func fixtureCC(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cc.db")
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	for _, q := range []string{
		`PRAGMA journal_mode=WAL`,
		`CREATE TABLE providers(id TEXT,app_type TEXT,name TEXT,settings_config TEXT,is_current INTEGER,PRIMARY KEY(id,app_type))`,
		`CREATE TABLE provider_endpoints(id INTEGER PRIMARY KEY,provider_id TEXT,app_type TEXT,url TEXT)`,
		`CREATE TABLE proxy_config(app_type TEXT,proxy_enabled INTEGER,enabled INTEGER,listen_address TEXT,listen_port INTEGER,live_takeover_active INTEGER)`,
		`INSERT INTO providers VALUES ('p','claude','Fixture','{"env":{"ANTHROPIC_BASE_URL":"https://upstream.example","ANTHROPIC_AUTH_TOKEN":"fixture"}}',1)`,
		`INSERT INTO provider_endpoints VALUES(1,'p','claude','https://endpoint.example')`,
	} {
		if _, e = db.Exec(q); e != nil {
			t.Fatal(e)
		}
	}
	return path
}
func TestCCOnlineBackupAndCompareAndSwapTransaction(t *testing.T) {
	path := fixtureCC(t)
	ctx := context.Background()
	inspect, e := InspectCC(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	p := inspect.Providers[0]
	endpointID := int64(1)
	mutations := []CCMutation{{App: "claude", ProviderID: "p", Expected: p.Settings, Updated: `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:18080/r/test"}}`}, {App: "claude", ProviderID: "p", EndpointID: &endpointID, Expected: "stale", Updated: "http://127.0.0.1:18080/r/endpoint"}}
	_, e = ApplyCC(ctx, path, t.TempDir(), mutations)
	var me *MutationError
	if !errors.As(e, &me) || me.Code != "CCSWITCH_DB_CHANGED_CONCURRENTLY" {
		t.Fatal(e)
	}
	after, e := InspectCC(ctx, path)
	if e != nil || after.Providers[0].Settings != p.Settings {
		t.Fatal("partial transaction committed", e)
	}
	mutations[1].Expected = "https://endpoint.example"
	backup, e := ApplyCC(ctx, path, t.TempDir(), mutations)
	if e != nil {
		t.Fatal(e)
	}
	old, e := InspectCC(ctx, backup)
	if e != nil || old.Providers[0].Settings != p.Settings || old.Endpoints[0].URL != "https://endpoint.example" {
		t.Fatal("online backup mismatch", e)
	}
	after, e = InspectCC(ctx, path)
	if e != nil || after.Endpoints[0].URL != mutations[1].Updated {
		t.Fatal("endpoint not changed", e)
	}
}
func TestCCModesUseAppEnabledAndLiveEvidence(t *testing.T) {
	p := CCProxy{ProxyEnabled: true, Enabled: false, Address: "0.0.0.0", Port: 15721}
	mode, _ := DetectCCMode("claude", p, true, "https://upstream.example")
	if mode != "ordinary" {
		t.Fatal(mode)
	}
	p.Enabled = true
	mode, _ = DetectCCMode("codex", p, true, "http://127.0.0.1:15721/v1")
	if mode != "local-proxy" {
		t.Fatal(mode)
	}
	mode, _ = DetectCCMode("claude", p, true, "https://upstream.example")
	if mode != "inconsistent" {
		t.Fatal(mode)
	}
}

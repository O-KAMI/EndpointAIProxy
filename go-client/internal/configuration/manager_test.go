package configuration

import (
	"context"
	"database/sql"
	"encoding/json"
	"endpointai/client/internal/state"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fixtureProtector struct{}

func (fixtureProtector) Protect(s string) ([]byte, error)   { return []byte(s), nil }
func (fixtureProtector) Unprotect(b []byte) (string, error) { return string(b), nil }
func fixtureManager(t *testing.T) (*Manager, Profile) {
	t.Helper()
	dir := t.TempDir()
	s, e := state.Open(filepath.Join(dir, "state.db"), fixtureProtector{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return &Manager{Store: s, Origin: "http://127.0.0.1:18080", BackupRoot: filepath.Join(dir, "backups")}, Profile{SID: fixtureProfileSID(t), Home: filepath.Join(dir, "home")}
}
func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte(content), 0600); e != nil {
		t.Fatal(e)
	}
}
func TestManagerAttachIdempotentDetachPreservesOtherUserEdits(t *testing.T) {
	m, p := fixtureManager(t)
	ctx := context.Background()
	path := configPath(p, "claude")
	writeFixture(t, path, `{"env":{"ANTHROPIC_AUTH_TOKEN":"fixture"}}`)
	rs, e := m.Reconcile(ctx, []Profile{p})
	if e != nil || !rs[0].Changed {
		t.Fatal(rs, e)
	}
	routes, e := m.Store.ListRoutes(ctx)
	if e != nil || len(routes) != 1 || routes[0].OriginalBaseURL != "https://api.anthropic.com" {
		t.Fatal(routes, e)
	}
	if routes[0].Status != 3 || len(routes[0].RouteID) != 22 || rs[0].Status != 3 {
		t.Fatal("attached status/route wire identity incompatible", routes[0], rs[0])
	}
	again, e := m.Reconcile(ctx, []Profile{p})
	if e != nil || again[0].Changed || again[0].RouteID != rs[0].RouteID {
		t.Fatal(again, e)
	}
	b, _ := os.ReadFile(path)
	var root map[string]any
	_ = json.Unmarshal(b, &root)
	root["user_edit"] = "retain"
	b, _ = json.Marshal(root)
	_ = os.WriteFile(path, b, 0600)
	_, e = m.DetachAll(ctx, []Profile{p})
	if e != nil {
		t.Fatal(e)
	}
	b, _ = os.ReadFile(path)
	_ = json.Unmarshal(b, &root)
	if root["user_edit"] != "retain" || root["env"].(map[string]any)["ANTHROPIC_AUTH_TOKEN"] != "fixture" || root["env"].(map[string]any)["ANTHROPIC_BASE_URL"] != "https://api.anthropic.com" {
		t.Fatal("detach lost fields")
	}
	routes, _ = m.Store.ListRoutes(ctx)
	if len(routes) != 0 {
		t.Fatal(routes)
	}
}
func TestManagerDetachRespectsUserChangedBaseURL(t *testing.T) {
	m, p := fixtureManager(t)
	ctx := context.Background()
	path := configPath(p, "codex")
	writeFixture(t, path, "model = \"fixture\"\n")
	if _, e := m.Reconcile(ctx, []Profile{p}); e != nil {
		t.Fatal(e)
	}
	writeFixture(t, path, "openai_base_url = \"https://user.example/v1\"\n")
	if _, e := m.DetachAll(ctx, []Profile{p}); e == nil {
		t.Fatal("detach ignored user ownership")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "openai_base_url = \"https://user.example/v1\"\n" {
		t.Fatal(string(b))
	}
	routes, _ := m.Store.ListRoutes(ctx)
	if len(routes) != 1 {
		t.Fatal("lost recovery route")
	}
}
func TestManagerAllowlistRestoresAttachedConfig(t *testing.T) {
	m, p := fixtureManager(t)
	ctx := context.Background()
	path := configPath(p, "codex")
	writeFixture(t, path, "openai_base_url = \"https://user.example/v1\"\n")
	if _, e := m.Reconcile(ctx, []Profile{p}); e != nil {
		t.Fatal(e)
	}
	m.Allowlisted = func(s string) bool { return s == "https://user.example/v1" }
	if _, e := m.Reconcile(ctx, []Profile{p}); e != nil {
		t.Fatal(e)
	}
	routes, _ := m.Store.ListRoutes(ctx)
	if len(routes) != 0 {
		t.Fatal(routes)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "openai_base_url = \"https://user.example/v1\"\n" {
		t.Fatal(string(b))
	}
}
func TestManagerCCOrdinarySyncAndDetach(t *testing.T) {
	m, p := fixtureManager(t)
	ctx := context.Background()
	src := fixtureCC(t)
	path := filepath.Join(p.Home, ".cc-switch", "cc-switch.db")
	b, e := os.ReadFile(src)
	if e != nil {
		t.Fatal(e)
	}
	writeFixture(t, path, string(b))
	writeFixture(t, configPath(p, "claude"), `{"env":{"ANTHROPIC_BASE_URL":"https://upstream.example","ANTHROPIC_AUTH_TOKEN":"fixture-live"}}`)
	rs, e := m.Reconcile(ctx, []Profile{p})
	if e != nil {
		t.Fatal(rs, e)
	}
	inspect, e := InspectCC(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := ccTransform("claude", inspect.Providers[0].Settings, "http://127.0.0.1:18080/r/inspection", false)
	if e != nil {
		t.Fatal(e)
	}
	live, _ := os.ReadFile(configPath(p, "claude"))
	lt, e := Claude(live, "http://127.0.0.1:18080/r/inspection", false)
	if e != nil || lt.Previous != parsed.Previous {
		t.Fatal("live config not synced", e)
	}
	routes, _ := m.Store.ListRoutes(ctx)
	if len(routes) != 2 {
		t.Fatal(routes)
	}
	if _, e = m.DetachAll(ctx, []Profile{p}); e != nil {
		t.Fatal(e)
	}
	inspect, e = InspectCC(ctx, path)
	if e != nil || inspect.Endpoints[0].URL != "https://endpoint.example" {
		t.Fatal(inspect, e)
	}
	routes, _ = m.Store.ListRoutes(ctx)
	if len(routes) != 0 {
		t.Fatal(routes)
	}
}

func TestInspectReportsCurrentUnattachedAndBypassedEndpointsWithoutWriting(t *testing.T) {
	m, p := fixtureManager(t)
	ctx := context.Background()
	path := configPath(p, "claude")
	input := `{"env":{"ANTHROPIC_BASE_URL":"https://user.example","ANTHROPIC_MODEL":"fixture-model","ANTHROPIC_AUTH_TOKEN":"fixture-secret"}}`
	writeFixture(t, path, input)
	m.Allowlisted = func(s string) bool { return s == "https://user.example" }
	assets, e := m.Inspect(ctx, []Profile{p})
	if e != nil || len(assets) != 1 {
		t.Fatal(assets, e)
	}
	a := assets[0]
	if !a.Bypassed || a.Source != 1 || a.Model != "fixture-model" || a.OriginalBaseURL != "https://user.example" || a.RouteStatus != 7 {
		t.Fatal(a)
	}
	routes, _ := m.Store.ListRoutes(ctx)
	if len(routes) != 0 {
		t.Fatal("inspection wrote routes")
	}
	b, _ := os.ReadFile(path)
	if string(b) != input {
		t.Fatal("inspection wrote config")
	}
	encoded, _ := json.Marshal(assets)
	if strings.Contains(string(encoded), "fixture-secret") {
		t.Fatal("secret in metadata")
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	assets, e = m.Inspect(ctx, []Profile{p})
	if e != nil || len(assets) != 0 {
		t.Fatal("deleted config still reported", assets, e)
	}
}

func TestManagerCCLocalProxyLeavesListenerAndQoderUntouched(t *testing.T) {
	m, p := fixtureManager(t)
	ctx := context.Background()
	src := fixtureCC(t)
	path := filepath.Join(p.Home, ".cc-switch", "cc-switch.db")
	b, e := os.ReadFile(src)
	if e != nil {
		t.Fatal(e)
	}
	writeFixture(t, path, string(b))
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	_, e = db.Exec(`INSERT INTO proxy_config VALUES('claude',1,1,'127.0.0.1',15721,1)`)
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	livePath := configPath(p, "claude")
	input := `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:15721","ANTHROPIC_AUTH_TOKEN":"fixture"}}`
	writeFixture(t, livePath, input)
	qoderPath := filepath.Join(p.Home, ".qoder", "config.json")
	writeFixture(t, qoderPath, `{"fixture":"untouched"}`)
	rs, e := m.Reconcile(ctx, []Profile{p})
	if e != nil || rs[0].Mode != "local-proxy" {
		t.Fatal(rs, e)
	}
	b, _ = os.ReadFile(livePath)
	if string(b) != input {
		t.Fatal("CC Switch listener changed")
	}
	if _, e = m.DetachAll(ctx, []Profile{p}); e != nil {
		t.Fatal(e)
	}
	b, _ = os.ReadFile(livePath)
	if string(b) != input {
		t.Fatal("detach changed listener")
	}
	b, _ = os.ReadFile(qoderPath)
	if string(b) != `{"fixture":"untouched"}` {
		t.Fatal("Qoder changed")
	}
}
func TestManagerRefusesUnownedLocalRoute(t *testing.T) {
	m, p := fixtureManager(t)
	ctx := context.Background()
	path := configPath(p, "codex")
	input := "openai_base_url = \"http://127.0.0.1:18080/r/missing\"\n"
	writeFixture(t, path, input)
	if _, e := m.Reconcile(ctx, []Profile{p}); e == nil {
		t.Fatal("unrecoverable route overwritten")
	}
	b, _ := os.ReadFile(path)
	if string(b) != input {
		t.Fatal("unrecoverable config changed")
	}
}

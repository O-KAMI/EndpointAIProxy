package configuration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCodexChatGPTDefaultOrigin(t *testing.T) {
	m, p := fixtureManager(t)
	ctx := context.Background()
	path := configPath(p, "codex")
	writeFixture(t, path, "model = 'fixture'\n")
	authPath := filepath.Join(p.Home, ".codex", "auth.json")
	auth := `{"auth_mode":"chatgpt","tokens":{"access_token":"synthetic-not-a-token"}}`
	writeFixture(t, authPath, auth)
	m.Allowlisted = func(origin string) bool { return strings.HasPrefix(origin, "https://api.openai.com/") }
	assets, err := m.Inspect(ctx, []Profile{p})
	if err != nil || len(assets) != 1 || assets[0].OriginalBaseURL != "https://chatgpt.com/backend-api/codex" || assets[0].Bypassed {
		t.Fatal("ChatGPT destination was classified as API key traffic", assets, err)
	}
	if _, err = m.Reconcile(ctx, []Profile{p}); err != nil {
		t.Fatal(err)
	}
	routes, err := m.Store.ListRoutes(ctx)
	if err != nil || len(routes) != 1 || routes[0].OriginalBaseURL != "https://chatgpt.com/backend-api/codex" {
		t.Fatal(routes, err)
	}
	if _, err = m.Reconcile(ctx, []Profile{p}); err != nil {
		t.Fatal("repeat attachment", err)
	}
	if _, err = m.DetachAll(ctx, []Profile{p}); err != nil {
		t.Fatal("detach", err)
	}
	b, _ := os.ReadFile(path)
	if !bytes.Contains(b, []byte("https://chatgpt.com/backend-api/codex")) {
		t.Fatal("detach restored the wrong login mode destination")
	}
	b, _ = os.ReadFile(authPath)
	if string(b) != auth {
		t.Fatal("authentication material changed")
	}
}

func TestCCSwitchCodexAuthIsProviderSpecific(t *testing.T) {
	for _, tt := range []struct{ mode, want string }{
		{"chatgpt", "https://chatgpt.com/backend-api/codex"},
		{"apikey", "https://api.openai.com/v1"},
		{"", "https://api.openai.com/v1"},
	} {
		settings, _ := json.Marshal(map[string]any{"config": "model='fixture'\n", "auth": map[string]any{"auth_mode": tt.mode}})
		got, err := ccTransform("codex", string(settings), "http://127.0.0.1:18080/r/fixture", false)
		if err != nil || got.Previous != tt.want {
			t.Fatal(tt.mode, got.Previous, err)
		}
		var root map[string]json.RawMessage
		_ = json.Unmarshal(got.Content, &root)
		if !bytes.Contains(root["auth"], []byte(tt.mode)) {
			t.Fatal("provider auth changed")
		}
	}
}

func TestCCSwitchChatGPTAttachRestoreAndAuthPreservation(t *testing.T) {
	m, p := fixtureManager(t)
	ctx := context.Background()
	ccPath := filepath.Join(p.Home, ".cc-switch", "cc-switch.db")
	b, err := os.ReadFile(fixtureCC(t))
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, ccPath, string(b))
	db, err := sql.Open("sqlite", ccPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	settings := `{"config":"model='fixture'\n","auth":{"auth_mode":"chatgpt","tokens":{"access_token":"synthetic-not-a-token"}}}`
	if _, err = db.Exec(`INSERT INTO providers VALUES('chatgpt','codex','Fixture',?,1)`, settings); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, configPath(p, "codex"), "model='fixture'\n")
	writeFixture(t, filepath.Join(p.Home, ".codex", "auth.json"), `{"auth_mode":"chatgpt"}`)
	for repeat := 0; repeat < 2; repeat++ {
		if _, err = m.Reconcile(ctx, []Profile{p}); err != nil {
			t.Fatal(err)
		}
	}
	routes, _ := m.Store.ListRoutes(ctx)
	found := false
	for _, route := range routes {
		if route.ProviderID == "codex:chatgpt" {
			found = route.OriginalBaseURL == codexChatGPTOrigin
		}
	}
	if !found {
		t.Fatal("CC Switch ChatGPT route missing or has API origin", routes)
	}
	if _, err = m.DetachAll(ctx, []Profile{p}); err != nil {
		t.Fatal(err)
	}
	var saved string
	if err = db.QueryRow(`SELECT settings_config FROM providers WHERE app_type='codex'`).Scan(&saved); err != nil {
		t.Fatal(err)
	}
	var before, after map[string]any
	_ = json.Unmarshal([]byte(settings), &before)
	_ = json.Unmarshal([]byte(saved), &after)
	if !reflect.DeepEqual(before["auth"], after["auth"]) || !strings.Contains(saved, codexChatGPTOrigin) {
		t.Fatal("provider authentication or restored destination changed")
	}
}

func TestCodexUnknownAuthDoesNotGuessOrWrite(t *testing.T) {
	m, p := fixtureManager(t)
	path := configPath(p, "codex")
	original := "model='fixture'\n"
	writeFixture(t, path, original)
	writeFixture(t, filepath.Join(p.Home, ".codex", "auth.json"), `{"auth_mode":"unknown-future-mode"}`)
	if _, err := m.Reconcile(context.Background(), []Profile{p}); err == nil {
		t.Fatal("unknown authentication mode accepted")
	}
	b, _ := os.ReadFile(path)
	if string(b) != original {
		t.Fatal("config changed before authentication mode was confirmed")
	}
	// An explicit URL is authoritative and does not require reading credentials.
	writeFixture(t, path, "openai_base_url='https://explicit.example/v1'\n")
	if _, err := m.Reconcile(context.Background(), []Profile{p}); err != nil {
		t.Fatal("explicit destination should not depend on implicit auth defaults", err)
	}
}

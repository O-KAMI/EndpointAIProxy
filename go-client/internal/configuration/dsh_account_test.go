package configuration

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"endpointai/client/internal/proxy"
)

func desktopAccountFixture(t *testing.T) (*Manager, Profile, string, *proxy.AccountListeners) {
	t.Helper()
	m, p := fixtureManager(t)
	p.DSHVersion, p.DSHDesktopAccountVerified = DSHDesktopSupportedVersion, true
	m.EnableDSH = true
	listeners := proxy.NewAccountListeners(http.NotFoundHandler())
	t.Cleanup(listeners.Close)
	m.AccountOrigin, m.PruneAccountOrigins = listeners.Ensure, listeners.Prune
	root := filepath.Join(p.Home, ".dsh")
	path := writeDSHFixture(t, p, root, "desktop", "- id: ui-chat\n  config: {theme: retained}\n")
	writeFixture(t, filepath.Join(filepath.Dir(path), "cordis.yml"), "[]\n")
	return m, p, path, listeners
}

func TestDesktopAccountAttachRestartDetachAndCredentialOwnership(t *testing.T) {
	m, p, path, listeners := desktopAccountFixture(t)
	credential := filepath.Join(p.Home, ".dsh", ".credentials.yaml")
	writeFixture(t, credential, "synthetic-opaque-grant: untouched\n")
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		results, err := m.Reconcile(ctx, []Profile{p})
		if err != nil {
			t.Fatal(results, err)
		}
		items := dshOnly(results)
		if len(items) != 1 || items[0].Status != 3 || items[0].Changed != (i == 0) {
			t.Fatal(items)
		}
	}
	routes, err := m.Store.ListRoutes(ctx)
	if err != nil || len(routes) != 1 || routes[0].OriginalBaseURL != "https://api.deepseek.com" {
		t.Fatal(routes, err)
	}
	origin := routes[0].InjectedBaseURL
	listeners.Close()
	if _, err := m.Reconcile(ctx, []Profile{p}); err != nil {
		t.Fatal("origin restoration", err)
	}
	routes, _ = m.Store.ListRoutes(ctx)
	if routes[0].InjectedBaseURL != origin {
		t.Fatal("origin changed after restart")
	}
	content, _ := os.ReadFile(path)
	writeFixture(t, path, string(content)+"- id: user-edit\n  config: {preserve: true}\n")
	m.EnableDSH = false
	if results, err := m.DetachAll(ctx, []Profile{p}); err != nil {
		t.Fatal(results, err)
	}
	content, _ = os.ReadFile(path)
	if strings.Contains(string(content), "inferenceOrigin") || !strings.Contains(string(content), "user-edit") || !strings.Contains(string(content), "theme: retained") {
		t.Fatal("detach lost ownership boundaries")
	}
	grant, _ := os.ReadFile(credential)
	if string(grant) != "synthetic-opaque-grant: untouched\n" {
		t.Fatal("credential storage changed")
	}
	routes, _ = m.Store.ListRoutes(ctx)
	if len(routes) != 0 {
		t.Fatal("account route not retired")
	}
}

func TestDesktopAccountRefusesUserChangedManagedRows(t *testing.T) {
	m, p, path, _ := desktopAccountFixture(t)
	if _, err := m.Reconcile(context.Background(), []Profile{p}); err != nil {
		t.Fatal(err)
	}
	routes, _ := m.Store.ListRoutes(context.Background())
	content, _ := os.ReadFile(path)
	modified := strings.Replace(string(content), routes[0].InjectedBaseURL, "https://user.example", 1)
	writeFixture(t, path, modified)
	if _, err := m.DetachAll(context.Background(), []Profile{p}); err == nil {
		t.Fatal("user change was overwritten")
	}
	content, _ = os.ReadFile(path)
	if string(content) != modified {
		t.Fatal("user configuration changed")
	}
	routes, _ = m.Store.ListRoutes(context.Background())
	if len(routes) != 1 {
		t.Fatal("recovery route discarded")
	}
}

func TestUnverifiedUnmanagedDesktopDoesNotBlockClaudeEnable(t *testing.T) {
	m, p, path, _ := desktopAccountFixture(t)
	m.ExcludeCodex = true
	p.DSHDesktopAccountVerified = false
	writeFixture(t, configPath(p, "claude"), `{"env":{"ANTHROPIC_BASE_URL":"https://claude.example"}}`)
	before, _ := os.ReadFile(path)
	results, err := m.Reconcile(context.Background(), []Profile{p})
	items := dshOnly(results)
	if err != nil || len(items) != 1 || items[0].Status != 5 || items[0].ErrorCode != "DSH_DESKTOP_ACCOUNT_UNVERIFIED" {
		t.Fatal("unmanaged unverified Desktop should remain unsupported", items, err)
	}
	after, _ := os.ReadFile(path)
	routes, _ := m.Store.ListRoutes(context.Background())
	if string(after) != string(before) || len(routes) != 1 || routes[0].AgentType != 0 {
		t.Fatal("unverified Desktop was attached or Claude was not enabled", routes)
	}
	p.DSHDesktopAccountVerified = true
	if _, err := m.Reconcile(context.Background(), []Profile{p}); err != nil {
		t.Fatal(err)
	}
	managed, _ := os.ReadFile(path)
	p.DSHDesktopAccountVerified = false
	if _, err := m.Reconcile(context.Background(), []Profile{p}); err == nil {
		t.Fatal("owned Desktop lost verification without blocking")
	}
	after, _ = os.ReadFile(path)
	if string(after) != string(managed) {
		t.Fatal("unverified owned Desktop configuration changed")
	}
}

func TestDesktopAccountRequiresVerifiedRuntimeAndCanonicalProfile(t *testing.T) {
	for _, mode := range []string{"unverified-runtime", "base-overlay", "unverified-base-overlay"} {
		t.Run(mode, func(t *testing.T) {
			m, p, path, _ := desktopAccountFixture(t)
			if mode != "base-overlay" {
				p.DSHDesktopAccountVerified = false
			}
			if mode != "unverified-runtime" {
				writeFixture(t, filepath.Join(filepath.Dir(path), "cordis.yml"), "- id: unknown\n  config: {}\n")
			}
			before, _ := os.ReadFile(path)
			results, err := m.Reconcile(context.Background(), []Profile{p})
			if mode == "unverified-runtime" {
				items := dshOnly(results)
				if err != nil || len(items) != 1 || items[0].Status != 5 || items[0].ErrorCode != "DSH_DESKTOP_ACCOUNT_UNVERIFIED" {
					t.Fatal("unverified unmanaged account should remain unsupported", items, err)
				}
			} else if err == nil {
				t.Fatal("unverified account setup accepted")
			}
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Fatal("unverified configuration modified")
			}
			routes, _ := m.Store.ListRoutes(context.Background())
			if len(routes) != 0 {
				t.Fatal("unverified route created")
			}
		})
	}
}

func TestDesktopHostProofDoesNotAuthorizeAnotherDSHRoot(t *testing.T) {
	m, p, _, _ := desktopAccountFixture(t)
	root := filepath.Join(p.Home, "another-dsh-home")
	p.DSHHomes = []string{root}
	path := writeDSHFixture(t, p, root, "desktop", "- id: ui-chat\n  config: {theme: retained}\n")
	writeFixture(t, filepath.Join(filepath.Dir(path), "cordis.yml"), "[]\n")
	before, _ := os.ReadFile(path)
	docs, err := dshDocuments(p)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, doc := range docs {
		if doc.path != path {
			continue
		}
		found = true
		results, err := m.dshAccountProfile(context.Background(), p, doc, false)
		if err == nil || len(results) != 1 || results[0].ErrorCode != "DSH_DESKTOP_ACCOUNT_UNVERIFIED" {
			t.Fatal("Desktop proof escaped its profile", results, err)
		}
	}
	after, _ := os.ReadFile(path)
	routes, _ := m.Store.ListRoutes(context.Background())
	if !found || string(before) != string(after) || len(routes) != 0 {
		t.Fatal("unverified profile modified or routed")
	}
}

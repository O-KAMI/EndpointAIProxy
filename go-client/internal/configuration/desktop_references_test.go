package configuration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDesktopAccountAllowsUnreferencedCodexRouteRetirement(t *testing.T) {
	m, p, _, _ := desktopAccountFixture(t)
	path := configPath(p, "codex")
	writeFixture(t, path, "openai_base_url='https://codex.example/v1'\n")
	if _, err := m.Reconcile(context.Background(), []Profile{p}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.DetachAll(context.Background(), []Profile{p}); err != nil {
		t.Fatal(err)
	}
	routes, err := m.Store.ListRoutes(context.Background())
	if err != nil || len(routes) != 0 {
		t.Fatal("verified Desktop prevented Codex route retirement", len(routes), err)
	}
	if _, err = m.DetachAll(context.Background(), []Profile{p}); err != nil {
		t.Fatal("repeat detach failed", err)
	}
}

func TestDesktopAccountReferenceScanRemainsConservative(t *testing.T) {
	for _, kind := range []string{"unverified-host", "overlay", "base", "include", "dynamic", "url-reference"} {
		t.Run(kind, func(t *testing.T) {
			m, p, path, _ := desktopAccountFixture(t)
			writeFixture(t, configPath(p, "codex"), "openai_base_url='https://codex.example/v1'\n")
			if _, err := m.Reconcile(context.Background(), []Profile{p}); err != nil {
				t.Fatal(err)
			}
			routes, _ := m.Store.ListRoutes(context.Background())
			var injected string
			for _, route := range routes {
				if route.AgentType == 1 {
					injected = route.InjectedBaseURL
				}
			}
			switch kind {
			case "unverified-host":
				p.DSHDesktopAccountVerified = false
			case "overlay":
				p.DSHOverlaysUnknown = true
				p.DSHDesktopAccountVerified = false
			case "base":
				writeFixture(t, filepath.Join(filepath.Dir(path), "cordis.yml"), "- id: unknown\n")
			case "include":
				b, _ := os.ReadFile(path)
				writeFixture(t, path, string(b)+"- id: external\n  include: ./unknown.yml\n")
			case "dynamic":
				b, _ := os.ReadFile(path)
				writeFixture(t, path, string(b)+"- id: unrelated\n  config: {endpoint: '${ENDPOINT}'}\n")
			case "url-reference":
				b, _ := os.ReadFile(path)
				writeFixture(t, path, string(b)+"- id: unrelated\n  config: {endpoint: '"+injected+"'}\n")
			}
			if _, err := m.DetachAll(context.Background(), []Profile{p}); err != nil && kind == "url-reference" {
				t.Fatal(err)
			}
			routes, _ = m.Store.ListRoutes(context.Background())
			found := false
			for _, route := range routes {
				found = found || route.AgentType == 1
			}
			if !found {
				t.Fatal("unverified or still referenced origin was discarded")
			}
			content, _ := os.ReadFile(path)
			if kind == "url-reference" && !strings.Contains(string(content), injected) {
				t.Fatal("unowned URL was modified")
			}
		})
	}
}

func TestVerifiedDesktopReferencesIgnoreUnrelatedNodeAmbiguity(t *testing.T) {
	m, p, _, _ := desktopAccountFixture(t)
	p.DSHOverlaysUnknown = true
	p.DSHDesktopReferencesVerified = true
	// Desktop provenance independently verifies its packaged host and rejects
	// conflicting Desktop launches; generic Node completeness is a CLI concern.
	if _, err := m.references(context.Background(), p); err != nil {
		t.Fatal("verified Desktop was blocked by generic CLI completeness", err)
	}
	p.DSHDesktopReferencesVerified = false
	if _, err := m.references(context.Background(), p); err == nil {
		t.Fatal("unknown DSH launch scope was treated as complete")
	}
	p.DSHDesktopReferencesVerified = true
	writeDSHFixture(t, p, filepath.Join(p.Home, ".dsh"), "web", dshDeepSeekFixture)
	if _, err := m.references(context.Background(), p); err == nil {
		t.Fatal("unverified non-Desktop profile was treated as complete")
	}
}

package configuration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExplicitDSHProviderDoesNotDependOnProductReleaseNumber(t *testing.T) {
	for _, version := range []string{"0.2.1-rc.3", "0.2.1-rc.4", "0.3.0", ""} {
		t.Run(version, func(t *testing.T) {
			m, p := fixtureManager(t)
			m.EnableDSH = true
			p.DSHVersion = version
			writeDSHFixture(t, p, filepath.Join(p.Home, ".dsh"), "headless", dshDeepSeekFixture)
			results, err := m.Reconcile(context.Background(), []Profile{p})
			if err != nil || len(dshOnly(results)) != 1 || dshOnly(results)[0].Status != 3 {
				t.Fatal(results, err)
			}
		})
	}
}

func TestDesktopAccountDoesNotSkipExplicitAPIKeyProvider(t *testing.T) {
	m, p, path, _ := desktopAccountFixture(t)
	p.DSHVersion = "new-product-release-with-reviewed-contract"
	writeFixture(t, path, dshDeepSeekFixture)
	results, err := m.Reconcile(context.Background(), []Profile{p})
	if err != nil {
		t.Fatal(results, err)
	}
	routes, _ := m.Store.ListRoutes(context.Background())
	if len(routes) != 2 {
		t.Fatal("account route hid API-key provider", routes)
	}
	if _, err = m.DetachAll(context.Background(), []Profile{p}); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(path)
	if string(body) == "" {
		t.Fatal("user configuration lost")
	}
}

func TestDefaultDSHProviderIsVisibleWithoutUnsafeMutation(t *testing.T) {
	m, p := fixtureManager(t)
	m.EnableDSH = true
	path := writeDSHFixture(t, p, filepath.Join(p.Home, ".dsh"), "headless", "[]\n")
	results, err := m.Reconcile(context.Background(), []Profile{p})
	var defaults []Result
	for _, result := range results {
		if result.AgentType == dshAgent {
			defaults = append(defaults, result)
		}
	}
	if err != nil || len(defaults) != 1 || defaults[0].ErrorCode != "DSH_DEFAULT_PROVIDER_UNVERIFIED" {
		t.Fatal(results, err)
	}
	body, _ := os.ReadFile(path)
	if string(body) != "[]\n" {
		t.Fatal("unknown effective endpoint was overwritten")
	}
	endpoints, err := m.InspectDSH(context.Background(), []Profile{p})
	if err != nil || len(endpoints) != 1 || endpoints[0].RouteStatus != 5 {
		t.Fatal(endpoints, err)
	}
}

func TestOfficialAPIKeyCatalogIsNotRedirectedByModelFieldPresence(t *testing.T) {
	for _, models := range []string{"", "    models: null\n", "    models: []\n", "    models:\n      - id: deepseek-flash\n"} {
		m, p := fixtureManager(t)
		m.EnableDSH = true
		body := "- id: llm-deepseek\n  config:\n    baseURL: https://api.deepseek.com/anthropic\n" + models
		path := writeDSHFixture(t, p, filepath.Join(p.Home, ".dsh"), "headless", body)
		results, err := m.Reconcile(context.Background(), []Profile{p})
		if err != nil || len(dshOnly(results)) != 1 || dshOnly(results)[0].ErrorCode != "DSH_DYNAMIC_MODEL_CATALOG_UNSUPPORTED" {
			t.Fatal(results, err)
		}
		actual, _ := os.ReadFile(path)
		if strings.Contains(string(actual), "127.0.0.1") || string(actual) != body {
			t.Fatal("catalog-dependent official provider was modified")
		}
	}
}

package app

import (
	"context"
	"encoding/json"
	"endpointai/client/internal/configuration"
	"endpointai/client/internal/contracts"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDomainAllowlistRestoresAndReattachesIsolatedConfiguration(t *testing.T) {
	a := newControlApp(t, newFakeControl(t))
	ctx := context.Background()
	home := t.TempDir()
	path := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	original := `{"env":{"ANTHROPIC_BASE_URL":"https://api.openai.com/v1","OTHER":"preserved"}}`
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	profiles := []configuration.Profile{{SID: "isolated-domain-user", Home: home, Roaming: home, Local: home}}
	p := testPolicy(2)
	p.SchemaVersion = 2
	if err := a.ApplyPolicy(ctx, p, "fixture"); err != nil {
		t.Fatal(err)
	}
	reconcile := func(wantLocal bool) {
		t.Helper()
		if _, err := a.manager().Reconcile(ctx, profiles); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var config struct {
			Env map[string]string `json:"env"`
		}
		if err := json.Unmarshal(body, &config); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(config.Env["ANTHROPIC_BASE_URL"], "127.0.0.1:18080/r/") != wantLocal || config.Env["OTHER"] != "preserved" {
			t.Fatalf("wrong config: %s", body)
		}
		if !wantLocal && config.Env["ANTHROPIC_BASE_URL"] != "https://api.openai.com/v1" {
			t.Fatal("original target lost")
		}
	}
	reconcile(true)
	p.PolicyVersion++
	p.AllowlistedDomains = []string{"openai.com"}
	if err := a.ApplyPolicy(ctx, p, "fixture"); err != nil {
		t.Fatal(err)
	}
	reconcile(false)
	p.PolicyVersion++
	p.AllowlistedDomains = []string{}
	if err := a.ApplyPolicy(ctx, p, "fixture"); err != nil {
		t.Fatal(err)
	}
	reconcile(true)
}

func TestDomainPolicySnapshotsCacheAndVersionWatermark(t *testing.T) {
	a := newControlApp(t, newFakeControl(t))
	p := testPolicy(2)
	p.SchemaVersion = 2
	p.AllowlistedDomains = []string{"openai.com"}
	gateway := "https://gateway.example"
	p.RoutingRules = []contracts.RoutingRule{{Domain: "anthropic.com", RouteMode: "fixedGateway", GatewayOrigin: &gateway}}
	if err := a.ApplyPolicy(context.Background(), p, "synthetic-signature"); err != nil {
		t.Fatal(err)
	}
	p.AllowlistedDomains[0] = "mutated.example"
	*p.RoutingRules[0].GatewayOrigin = "https://mutated.example"
	if !a.Bypass("http://api.openai.com:8080/any/path") || a.Bypass("https://openai.com.evil.example") {
		t.Fatal("attachment matcher disagrees with policy")
	}
	copy := a.Policy()
	copy.AllowlistedDomains[0] = "changed.example"
	*copy.RoutingRules[0].GatewayOrigin = "https://changed.example"
	if *a.Policy().RoutingRules[0].GatewayOrigin != "https://gateway.example" {
		t.Fatal("mutable policy snapshot")
	}
	cached, err := a.Store.LoadPolicy(context.Background())
	if err != nil || cached.Policy.SchemaVersion != 2 || cached.Policy.AllowlistedDomains[0] != "openai.com" {
		t.Fatal(cached, err)
	}
	if err := a.ApplyPolicy(context.Background(), testPolicy(1), "older"); err != nil {
		t.Fatal(err)
	}
	if a.Policy().SchemaVersion != 2 {
		t.Fatal("accepted lower-version legacy policy")
	}
}

func TestSameVersionSchemaUpgradeDoesNotAllowSchemaDowngrade(t *testing.T) {
	a := newControlApp(t, newFakeControl(t))
	upgraded := testPolicy(1)
	upgraded.SchemaVersion = 2
	upgraded.AllowlistedDomains = []string{"openai.com"}
	if err := a.ApplyPolicy(context.Background(), upgraded, "synthetic-signature"); err != nil {
		t.Fatal(err)
	}
	if a.Policy().SchemaVersion != 2 || !a.Bypass("https://api.openai.com/v1") {
		t.Fatal("same-version schema upgrade was not applied")
	}
	if err := a.ApplyPolicy(context.Background(), testPolicy(1), "older-schema"); err != nil {
		t.Fatal(err)
	}
	if a.Policy().SchemaVersion != 2 {
		t.Fatal("same-version schema downgrade was applied")
	}
}

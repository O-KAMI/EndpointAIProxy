package app

import (
	"context"
	"encoding/json"
	"endpointai/client/internal/configuration"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"endpointai/client/internal/contracts"
	"endpointai/client/internal/platform"
	"endpointai/client/internal/proxy"
)

func TestDSHWireAPIIndependentOfCodex(t *testing.T) {
	cases := []struct {
		family, provider string
		want             contracts.AgentWireApi
	}{
		{"deepseekHarness", "dsh:messages:deepseek:scope", contracts.AgentWireApiAnthropicMessages},
		{"deepseekHarness", "dsh:responses:custom:scope", contracts.AgentWireApiOpenAiResponses},
		{"deepseekHarness", "dsh:chat:custom:scope", contracts.AgentWireApiChatCompletions},
		{"deepseekHarness", "dsh:unknown:search:scope", contracts.AgentWireApiUnknown},
		{"deepseekHarness", "bad", contracts.AgentWireApiUnknown},
		{"unknown", "dsh:responses:custom:scope", contracts.AgentWireApiUnknown},
		{"claude", "default", contracts.AgentWireApiAnthropicMessages},
		{"codex", "default", contracts.AgentWireApiOpenAiResponses},
	}
	for _, tc := range cases {
		if got := endpointWireAPI(tc.family, tc.provider); got != tc.want {
			t.Fatalf("%s/%s: %d", tc.family, tc.provider, got)
		}
	}
	route := contracts.Route{AgentType: int(contracts.AgentTypeDeepSeekHarness), ProviderID: "dsh:messages:deepseek:scope", UserSID: "user", RouteID: proxy.UUID()}
	if family(route) != "deepseekHarness" {
		t.Fatal("DSH classified as another agent")
	}
	if assetID(route) == assetID(contracts.Route{AgentType: 1, ProviderID: route.ProviderID, UserSID: route.UserSID}) {
		t.Fatal("DSH/Codex asset collision")
	}
}

func TestDSHOffFiltersHeartbeatAndHealthButLeavesRecoveryState(t *testing.T) {
	ctx := context.Background()
	a := newControlApp(t, newFakeControl(t))
	route := contracts.Route{RouteID: proxy.UUID(), UserSID: "user", AgentType: int(contracts.AgentTypeDeepSeekHarness), ProviderID: "dsh:messages:deepseek:scope", OriginalBaseURL: "https://api.deepseek.com/anthropic", Status: int(contracts.RouteStatusAttached), CreatedAtUTC: time.Now().UTC(), UpdatedAtUTC: time.Now().UTC()}
	if err := a.Store.UpsertRoute(ctx, route); err != nil {
		t.Fatal(err)
	}
	a.Profiles = func(context.Context) ([]platform.Profile, error) { return nil, nil }
	heartbeat, err := a.Heartbeat(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if heartbeat.Proxy.ActiveRouteCount != 0 || len(heartbeat.Agents) != 0 || len(heartbeat.Endpoints) != 0 {
		t.Fatalf("DSH off leaked metadata: %+v", heartbeat)
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	var health struct {
		RouteCount int `json:"routeCount"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if health.RouteCount != 0 {
		t.Fatal("DSH off counted route")
	}
	if stored, err := a.Store.FindRoute(ctx, route.RouteID); err != nil || stored == nil {
		t.Fatalf("recovery route removed: %v", err)
	}
	a.Options.EnableDSH = true
	heartbeat, err = a.Heartbeat(ctx)
	if err != nil || heartbeat.Proxy.ActiveRouteCount != 1 {
		t.Fatalf("DSH enabled: %+v %v", heartbeat.Proxy, err)
	}
}

func TestDSHRecoveryEntryInspectsLiveOverlayWithFeatureOff(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node unavailable")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write := func(path, value string) {
		t.Helper()
		if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, []byte(value), 0600); e != nil {
			t.Fatal(e)
		}
	}
	pkg := filepath.Join(home, ".local/bin/node_modules/@deepseek-ai/dsh")
	write(filepath.Join(pkg, "package.json"), `{"name":"@deepseek-ai/dsh","version":"0.2.1-alpha.5","bin":{"dsh":"lib/bin.js"}}`)
	entry := filepath.Join(pkg, "lib/bin.js")
	write(entry, "setInterval(()=>{},1000)")
	root := filepath.Join(home, "custom-dsh")
	profileDir := filepath.Join(root, "profiles/web")
	write(filepath.Join(profileDir, "package.json"), `{"dsh":{"profile":{"bundles":["@deepseek-ai/dsh-base","@deepseek-ai/dsh-headless"]}}}`)
	patch := filepath.Join(profileDir, "cordis.patch.yml")
	write(patch, "- id: llm-deepseek\n  config:\n    baseURL: https://synthetic.example.invalid/anthropic\n")
	ctx := context.Background()
	a := newControlApp(t, newFakeControl(t))
	a.Options.EnableDSH = true
	m := a.manager()
	p := configuration.Profile{SID: "fixture", Home: home, DSHHomes: []string{root}, DSHVersion: "0.2.1-alpha.5"}
	if _, err = m.Reconcile(ctx, []configuration.Profile{p}); err != nil {
		t.Fatal(err)
	}
	routes, err := a.Store.ListRoutes(ctx)
	if err != nil || len(routes) != 1 {
		t.Fatalf("attach: %v %v", routes, err)
	}
	command := exec.Command(node, entry, "web", "--patch", "overlay.yml")
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { command.Process.Kill(); command.Wait() }()
	a.Options.EnableDSH = false
	a.Options.DSHHomes = nil
	pp := []platform.Profile{{SID: p.SID, Home: home}}
	var prepared []configuration.Profile
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		prepared = a.configProfiles(ctx, pp)
		if len(prepared) == 1 && prepared[0].DSHOverlaysUnknown {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(prepared) != 1 || !prepared[0].DSHOverlaysUnknown || len(prepared[0].DSHHomes) == 0 {
		t.Fatalf("recovery metadata missing: %+v", prepared)
	}
	// Removing the profile must not retire a route still potentially used by the
	// live overlay. This also exercises the helper used by maintenance.
	if err = os.RemoveAll(profileDir); err != nil {
		t.Fatal(err)
	}
	prepared, err = PrepareConfigurationProfiles(ctx, m, pp, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.DetachAll(ctx, prepared); err == nil {
		t.Fatal("unknown live overlay allowed detach")
	}
	if remaining, err := a.Store.ListRoutes(ctx); err != nil || len(remaining) != 1 {
		t.Fatalf("route retired: %v %v", remaining, err)
	}
}

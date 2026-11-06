package app

import (
	"testing"
	"time"

	"endpointai/client/internal/configuration"
	"endpointai/client/internal/contracts"
	"endpointai/client/internal/proxy"
)

func TestInferenceVerificationRequiresCurrentSuccessfulPostAndRoute(t *testing.T) {
	a := newControlApp(t, newFakeControl(t))
	route := contracts.Route{RouteID: "synthetic-route", UserSID: "synthetic-user", AgentType: 11, ProviderID: "dsh:messages:deepseek:fixture", OriginalBaseURL: "https://synthetic.example/anthropic", InjectedBaseURL: "http://127.0.0.1:18080/r/synthetic-route", Status: 3}
	id := assetID(route)
	endpoint := func() contracts.AgentEndpointAsset {
		return contracts.AgentEndpointAsset{AssetID: id, LocalRouteURL: ptr(route.InjectedBaseURL), RouteStatus: contracts.RouteStatusAttached}
	}
	record := proxy.Record{Route: route, Started: time.Now(), Method: "POST", Inbound: "/r/synthetic-route/models", PolicyVersion: a.Policy().PolicyVersion}
	a.Observe(record, 200, "SUCCESS", time.Millisecond)
	item := endpoint()
	a.verifyEndpoint(&item, []contracts.Route{route})
	if item.VerificationState != "unverified" {
		t.Fatal("model listing counted as inference")
	}
	record.Inbound = "/r/synthetic-route/anthropic/v1/messages"
	a.Observe(record, 502, "GATEWAY_CONNECTION_FAILED", time.Millisecond)
	item = endpoint()
	a.verifyEndpoint(&item, []contracts.Route{route})
	if item.VerificationState != "unverified" {
		t.Fatal("failed inference counted as verified")
	}
	a.Observe(record, 200, "SUCCESS", time.Millisecond)
	item = endpoint()
	a.verifyEndpoint(&item, []contracts.Route{route})
	if item.VerificationState != "observed" || item.ObservedPolicyVersion == nil {
		t.Fatal("successful inference was not verified")
	}
	route.UpdatedAtUTC = time.Now() // idempotent maintenance is not a route change.
	item = endpoint()
	a.verifyEndpoint(&item, []contracts.Route{route})
	if item.VerificationState != "observed" {
		t.Fatal("maintenance invalidated unchanged route")
	}
	a.mu.Lock()
	a.policy.PolicyVersion++
	a.mu.Unlock()
	item = endpoint()
	a.verifyEndpoint(&item, []contracts.Route{route})
	if item.VerificationState != "unverified" {
		t.Fatal("old policy observation survived")
	}
}

func TestConfigurationChangeInvalidatesInflightInference(t *testing.T) {
	a := newControlApp(t, newFakeControl(t))
	route := contracts.Route{RouteID: "synthetic", UserSID: "synthetic-user", AgentType: 11, ProviderID: "dsh:messages:account:fixture", Status: 3}
	old := proxy.Record{Route: route, Started: time.Now().Add(-time.Minute), Method: "POST", Inbound: "/r/synthetic/messages", PolicyVersion: a.Policy().PolicyVersion}
	a.mu.Lock()
	a.noteConfigurationChangesLocked([]configuration.Result{{SID: route.UserSID, ProviderID: route.ProviderID, AgentType: 11, Changed: true}})
	a.mu.Unlock()
	a.Observe(old, 200, "SUCCESS", time.Millisecond)
	if _, ok := a.inference[assetID(route)]; ok {
		t.Fatal("old in-flight request verified a new configuration")
	}
	if !a.reloadRequired[assetID(route)] {
		t.Fatal("reload warning lost")
	}
}

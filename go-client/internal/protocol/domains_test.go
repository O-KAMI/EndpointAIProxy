package protocol

import (
	"endpointai/client/internal/contracts"
	"testing"
)

func TestDomainBoundariesAndCanonicalForms(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{"OpenAI.COM.", "openai.com"}, {"例子.公司", "xn--fsqu00a.xn--55qx5d"},
		{"[2001:0db8::1]", "2001:db8::1"}, {"127.0.0.1", "127.0.0.1"},
	} {
		got, err := NormalizeDomain(tc.value)
		if err != nil || got != tc.want {
			t.Fatalf("%q: %q %v", tc.value, got, err)
		}
	}
	for _, value := range []string{"", "*.openai.com", "https://openai.com", "openai.com:443", "openai.com/v1", "a..com", "-a.com", "a_.com"} {
		if _, err := NormalizeDomain(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	set := map[string]struct{}{"openai.com": {}, "127.0.0.1": {}, "2001:db8::1": {}}
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"https://openai.com", true}, {"http://API.OpenAI.COM.:8000/v1", true},
		{"https://fakeopenai.com", false}, {"https://openai.com.evil.com", false},
		{"https://evil.com/openai.com", false}, {"http://127.0.0.1:9999/v1", true},
		{"http://foo.127.0.0.1", false}, {"http://[2001:db8::1]:8080", true},
	} {
		if got := DomainAllowed(tc.url, set); got != tc.want {
			t.Fatalf("%q got %v", tc.url, got)
		}
	}
}

func TestRoutingSpecificityGatewayInheritanceAndLegacy(t *testing.T) {
	defaultGateway, otherGateway := "https://default.example", "https://other.example"
	p := contracts.Policy{SchemaVersion: 2, RouteMode: "fixedGateway", GatewayOrigin: &defaultGateway,
		RoutingRules: []contracts.RoutingRule{
			{Domain: "openai.com", RouteMode: "fixedGateway", GatewayOrigin: &otherGateway},
			{Domain: "api.openai.com", RouteMode: "passthroughOriginal"},
			{Domain: "deep.api.openai.com", RouteMode: "fixedGateway"},
		}}
	for _, tc := range []struct{ url, mode, gateway string }{
		{"https://openai.com/v1", "fixedGateway", otherGateway},
		{"https://x.api.openai.com/v1", "passthroughOriginal", defaultGateway},
		{"https://deep.api.openai.com/v1", "fixedGateway", defaultGateway},
		{"https://unmatched.example", "fixedGateway", defaultGateway},
	} {
		got := ResolveRoutingPolicy(tc.url, p)
		if got.RouteMode != tc.mode || *got.GatewayOrigin != tc.gateway {
			t.Fatalf("%q: %+v", tc.url, got)
		}
	}
	p.SchemaVersion = 1
	if got := ResolveRoutingPolicy("https://api.openai.com", p); got.RouteMode != p.RouteMode {
		t.Fatal("legacy policy changed")
	}
}

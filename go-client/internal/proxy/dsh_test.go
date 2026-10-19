package proxy

import (
	"context"
	"endpointai/client/internal/contracts"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDSHResourcePathsPreserveOriginalURL(t *testing.T) {
	for _, tc := range []struct{ base, provider, suffix, want string }{
		{"https://up.example/anthropic", "dsh:messages:deepseek:scope", "v1/messages", "/anthropic/v1/messages"},
		{"https://up.example/anthropic/v1/", "dsh:messages:deepseek:scope", "v1/files/file%2Fid", "/anthropic/v1/files/file%2Fid"},
		{"https://up.example/anthropic/v1", "dsh:messages:search:scope", "messages", "/anthropic/v1/messages"},
		{"https://up.example/v1", "dsh:chat:custom:scope", "chat/completions", "/v1/chat/completions"},
		{"https://up.example/v1", "dsh:responses:custom:scope", "responses", "/v1/responses"},
		{"https://up.example/v1", "dsh:messages:custom:scope", "v1/messages", "/v1/v1/messages"},
	} {
		t.Run(tc.provider+tc.suffix, func(t *testing.T) {
			route := contracts.Route{AgentType: 11, ProviderID: tc.provider, OriginalBaseURL: tc.base}
			for _, gateway := range []bool{false, true} {
				policy := contracts.Policy{RouteMode: "passthroughOriginal"}
				if gateway {
					origin := "https://gateway.example"
					policy.RouteMode = "fixedGateway"
					policy.GatewayOrigin = &origin
				}
				got, err := routeTarget(route, tc.suffix, "after=a%2Fb", policy)
				if err != nil || got.EscapedPath() != tc.want || got.RawQuery != "after=a%2Fb" || route.OriginalBaseURL != tc.base {
					t.Fatalf("target %v: %v", got, err)
				}
				if gateway && got.Host != "gateway.example" {
					t.Fatal(got)
				}
			}
		})
	}
	// Existing agents keep their original path semantics.
	got, err := routeTarget(contracts.Route{AgentType: 1, ProviderID: "direct", OriginalBaseURL: "https://up.example/v1"}, "v1/messages", "", contracts.Policy{})
	if err != nil || got.Path != "/v1/v1/messages" {
		t.Fatal(got, err)
	}
}

func TestDSHFilesHeadersBodyAndAttribution(t *testing.T) {
	body := "--fixture\r\nContent-Disposition: form-data; name=\"file\"; filename=\"fixture.png\"\r\n\r\nfixture-bytes\r\n--fixture--\r\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if r.URL.RequestURI() != "/anthropic/v1/files?limit=2" || string(raw) != body || r.Header.Get("Content-Type") != "multipart/form-data; boundary=fixture" || r.Header.Get("X-Api-Key") != "synthetic-not-a-key" || r.Header.Get("Anthropic-Beta") != "files-api-2025-04-14" {
			t.Error("DSH wire changed")
		}
		if r.Header.Get("X-Sf-Userid") != "fixture" || r.Header.Get("X-Sf-Ai-Agent") != "DeepSeekHarness" || r.Header.Get("X-Request-Id") == "forged" || r.Header.Get("X-Sf-Ai-Original-Base-Url") != "https://origin.example/anthropic/v1" {
			t.Error("DSH attribution changed")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"file-fixture"}`)
	}))
	defer upstream.Close()
	origin := upstream.URL
	route := contracts.Route{RouteID: fixtureID, UserSID: "macos:fixture", AgentType: 11, ProviderID: "dsh:messages:deepseek:scope", OriginalBaseURL: "https://origin.example/anthropic/v1"}
	h := Handler{Store: fixtureStore{route}, Policy: func() contracts.Policy {
		return contracts.Policy{Enabled: true, RouteMode: "fixedGateway", GatewayOrigin: &origin, AllowInsecureGateway: true}
	}, Transport: http.DefaultTransport, GatewayKey: []byte(strings.Repeat("s", 32)), DeviceID: func() string { return UUID() }}
	request := httptest.NewRequest("POST", "http://local/r/"+fixtureID+"/v1/files?limit=2", strings.NewReader(body)).WithContext(context.Background())
	request.Header.Set("Content-Type", "multipart/form-data; boundary=fixture")
	request.Header.Set("X-Api-Key", "synthetic-not-a-key")
	request.Header.Set("Anthropic-Beta", "files-api-2025-04-14")
	request.Header.Set("x-sf-userid", "forged")
	request.Header.Set("x-request-id", "forged")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != 200 || response.Body.String() != `{"id":"file-fixture"}` {
		t.Fatal(response.Code, response.Body.String())
	}
}

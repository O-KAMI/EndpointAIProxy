package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"endpointai/client/internal/contracts"
)

type routingTransport func(*http.Request) (*http.Response, error)

func (f routingTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDomainRoutingUsesSelectedModeForTargetAndHeaders(t *testing.T) {
	gateway := "https://default.example"
	for _, mode := range []string{"passthroughOriginal", "fixedGateway"} {
		t.Run(mode, func(t *testing.T) {
			p := contracts.Policy{SchemaVersion: 2, Enabled: true, RouteMode: "fixedGateway", GatewayOrigin: &gateway,
				RoutingRules: []contracts.RoutingRule{{Domain: "openai.com", RouteMode: mode}}}
			h := fixtureHandler("https://api.openai.com/v1")
			h.Policy = func() contracts.Policy { return p }
			h.UserID = func(string) string { return "00123" }
			h.DeviceID = func() string { return "test-device" }
			h.Transport = routingTransport(func(r *http.Request) (*http.Response, error) {
				wantHost := "api.openai.com"
				if mode == "fixedGateway" {
					wantHost = "default.example"
				}
				body, _ := io.ReadAll(r.Body)
				if r.URL.Host != wantHost || r.URL.RequestURI() != "/v1/responses?q=a%2Fb" || string(body) != "payload" {
					t.Fatalf("wrong forwarding: %v %s", r.URL, body)
				}
				if (r.Header.Get("X-Sf-Userid") == "00123") != (mode == "fixedGateway") {
					t.Fatal("headers used default rather than selected mode")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: ok\n\n"))}, nil
			})
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("POST", "/r/"+fixtureID+"/responses?q=a%2Fb", strings.NewReader("payload")))
			if w.Code != 200 || w.Body.String() != "data: ok\n\n" {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}

func TestDomainAllowlistWinsOverRouting(t *testing.T) {
	h := fixtureHandler("https://api.openai.com/v1")
	h.Snapshot = func() (contracts.Policy, map[string]struct{}) {
		return contracts.Policy{SchemaVersion: 2, Enabled: true, RoutingRules: []contracts.RoutingRule{{Domain: "openai.com", RouteMode: "fixedGateway"}}}, map[string]struct{}{"openai.com": {}}
	}
	h.Transport = routingTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("bypassed request reached transport")
		return nil, context.Canceled
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/r/"+fixtureID+"/responses", nil))
	if w.Code != 409 || !strings.Contains(w.Body.String(), "BASE_URL_ALLOWLIST_BYPASS") {
		t.Fatal(w.Code, w.Body.String())
	}
}

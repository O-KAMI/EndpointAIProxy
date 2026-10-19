package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"endpointai/client/internal/contracts"
	"endpointai/client/internal/observability"
)

type unavailableRoutes struct{}

func (unavailableRoutes) FindRoute(context.Context, string) (*contracts.Route, error) {
	return nil, errors.New("private database path")
}

type failedTransport struct{ err error }

func (f failedTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }

func TestPreflightFailuresHaveLocalEvidenceWithoutBodyCapture(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, code string
		status                   int
	}{
		{"method", "TRACE", "/r/" + fixtureID, "METHOD_NOT_ALLOWED", 405},
		{"invalid_route", "GET", "/r/invalid", "ROUTE_NOT_FOUND", 404},
		{"state", "GET", "/r/" + fixtureID, "ROUTE_STATE_READ_FAILED", 500},
		{"disabled", "GET", "/r/" + fixtureID, "PROXY_DISABLED", 500},
		{"target", "GET", "/r/" + fixtureID, "PROXY_TARGET_INVALID", 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := fixtureHandler("https://upstream.example/v1")
			if tc.name == "state" {
				h.Store = unavailableRoutes{}
			}
			if tc.name == "disabled" {
				h.Enabled = func() bool { return false }
			}
			if tc.name == "target" {
				h.Store = fixtureStore{contracts.Route{RouteID: fixtureID, OriginalBaseURL: "invalid"}}
			}
			observed := 0
			h.StartCapture = func(Record) Capture { t.Fatal("preflight opened body capture"); return nil }
			h.Observe = func(rec Record, status int, _ string, _ time.Duration) {
				observed++
				if observability.SafeID(rec.RequestID) == "" || !rec.Preflight || status != tc.status || rec.Failure.Code != tc.code {
					t.Fatalf("bad preflight evidence: %+v", rec.Failure)
				}
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
			if w.Code != tc.status || observed != 1 {
				t.Fatal("missing observation or changed external status")
			}
		})
	}
}

func TestDNSCauseIsClassifiedWithoutLeakingError(t *testing.T) {
	h := fixtureHandler("https://upstream.example/v1")
	h.Transport = failedTransport{&net.DNSError{Name: "secret.example", Err: "private-token", IsNotFound: true}}
	h.Observe = func(rec Record, status int, outcome string, _ time.Duration) {
		if rec.Failure.Class != "DNS_NOT_FOUND" || rec.Failure.Stage != "dns" || status != 502 || outcome != "GATEWAY_CONNECTION_FAILED" {
			t.Fatalf("missing DNS classification: %+v", rec.Failure)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/r/"+fixtureID, nil))
	if w.Code != 502 {
		t.Fatal(w.Code)
	}
}

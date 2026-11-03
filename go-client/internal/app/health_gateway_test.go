package app

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestHealthReportsAppliedGatewayInsteadOfBootstrap(t *testing.T) {
	a := newControlApp(t, newFakeControl(t))
	policy := a.Policy()
	origin := "http://scoped-gateway.example"
	policy.GatewayOrigin = &origin
	policy.PolicyVersion++
	if err := a.ApplyPolicy(context.Background(), policy, "fixture"); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	var health struct {
		GatewayOrigin string `json:"gatewayOrigin"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &health); err != nil || health.GatewayOrigin != origin {
		t.Fatal("effective gateway not exposed", health, err)
	}
}

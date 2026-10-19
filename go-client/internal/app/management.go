package app

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"endpointai/client/internal/configuration"
	"endpointai/client/internal/discovery"
)

func (a *App) HandlerWithManagement(enabled bool, token string) http.Handler {
	base := a.Handler()
	if !enabled {
		return base
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/management/") {
			base.ServeHTTP(w, r)
			return
		}
		header := r.Header.Get("Authorization")
		scheme, value, ok := strings.Cut(header, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || len(value) != len(token) || subtle.ConstantTimeCompare([]byte(value), []byte(token)) != 1 || len(token) < 32 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		profiles, e := a.Profiles(r.Context())
		if e != nil {
			w.WriteHeader(500)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "PROFILE_DISCOVERY_FAILED"})
			return
		}
		switch r.URL.Path {
		case "/management/discovery":
			if r.Method != "GET" {
				w.WriteHeader(405)
				return
			}
			agents, e := discovery.Discover(r.Context(), profiles)
			failures := []any{}
			if e != nil {
				failures = append(failures, map[string]string{"code": "DISCOVERY_COLLECTOR_FAILED"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"agents": agents, "failures": failures})
		case "/management/attach", "/management/detach":
			if r.Method != "POST" {
				w.WriteHeader(405)
				return
			}
			a.mutation.Lock()
			defer a.mutation.Unlock()
			manager := a.manager()
			cp := a.configProfiles(r.Context(), profiles)
			var results []configuration.Result
			var err error
			if r.URL.Path == "/management/detach" {
				results, err = manager.DetachAll(r.Context(), cp)
			} else {
				results, err = manager.Reconcile(r.Context(), cp)
			}
			a.logConfigResults(strings.TrimPrefix(r.URL.Path, "/management/"), results)
			failures := []any{}
			if err != nil {
				failures = append(failures, map[string]string{"errorCode": "CONFIG_OPERATION_FAILED"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"results": results, "failures": failures})
		default:
			w.WriteHeader(404)
		}
	})
}

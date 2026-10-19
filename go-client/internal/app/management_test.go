package app

import (
	"context"
	"endpointai/client/internal/platform"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestManagementDetachNeverAttachesAndAuthIsRequired(t *testing.T) {
	a := newControlApp(t, newFakeControl(t))
	home := t.TempDir()
	a.Profiles = func(context.Context) ([]platform.Profile, error) {
		return []platform.Profile{{SID: "synthetic-user", Home: home}}, nil
	}
	profiles, e := a.Profiles(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(profiles[0].Home, ".claude", "settings.json")
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	content := `{"env":{"ANTHROPIC_BASE_URL":"https://original.example"}}`
	if e = os.WriteFile(path, []byte(content), 0600); e != nil {
		t.Fatal(e)
	}
	token := "synthetic-management-token-32-bytes"
	h := a.HandlerWithManagement(true, token)
	r := httptest.NewRequest("POST", "/management/detach", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("unauthorized management accepted")
	}
	r = httptest.NewRequest("POST", "/management/detach", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	b, _ := os.ReadFile(path)
	routes, _ := a.Store.ListRoutes(context.Background())
	if string(b) != content || len(routes) != 0 {
		t.Fatal("detach created configuration/state mutations")
	}
}

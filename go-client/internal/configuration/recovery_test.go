package configuration

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"endpointai/client/internal/state"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"modernc.org/sqlite"
)

func installCCFixture(t *testing.T, p Profile) string {
	t.Helper()
	source := fixtureCC(t)
	path := filepath.Join(p.Home, ".cc-switch", "cc-switch.db")
	b, e := os.ReadFile(source)
	if e != nil {
		t.Fatal(e)
	}
	writeFixture(t, path, string(b))
	return path
}

func TestOwnershipHandoffDirectToCCAndBack(t *testing.T) {
	m, p := fixtureManager(t)
	ctx := context.Background()
	path := configPath(p, "claude")
	writeFixture(t, path, `{"env":{"ANTHROPIC_BASE_URL":"https://upstream.example","ANTHROPIC_AUTH_TOKEN":"synthetic"}}`)
	if _, e := m.Reconcile(ctx, []Profile{p}); e != nil {
		t.Fatal(e)
	}
	routes, _ := m.Store.ListRoutes(ctx)
	old := routes[0]
	cc := installCCFixture(t, p)
	db, e := sql.Open("sqlite", cc)
	if e != nil {
		t.Fatal(e)
	}
	settings, _ := json.Marshal(map[string]any{"env": map[string]string{"ANTHROPIC_BASE_URL": old.InjectedBaseURL}})
	if _, e = db.Exec("UPDATE providers SET settings_config=? WHERE id='p'", string(settings)); e != nil {
		t.Fatal(e)
	}
	db.Close()
	if _, e = m.Reconcile(ctx, []Profile{p}); e != nil {
		t.Fatal(e)
	}
	routes, _ = m.Store.ListRoutes(ctx)
	for _, r := range routes {
		if r.AgentType != 4 {
			t.Fatal("old direct ownership was not retired")
		}
		if r.ProviderID == "claude:p" && r.OriginalBaseURL != "https://upstream.example" {
			t.Fatal("lost true upstream during handoff")
		}
	}
	if e = os.Remove(cc); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Reconcile(ctx, []Profile{p}); e != nil {
		t.Fatal(e)
	}
	routes, _ = m.Store.ListRoutes(ctx)
	if len(routes) != 1 || routes[0].AgentType != 0 || routes[0].OriginalBaseURL != "https://upstream.example" {
		t.Fatalf("invalid reverse handoff: %+v", routes)
	}
}

func finishFailure(t *testing.T, m *Manager, path string, interfere bool) {
	t.Helper()
	db, e := sql.Open("sqlite", filepath.Join(filepath.Dir(m.BackupRoot), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	statement := ""
	if interfere {
		name := "synthetic_" + randomID()
		e = sqlite.RegisterScalarFunction(name, 0, func(*sqlite.FunctionContext, []driver.Value) (driver.Value, error) {
			b, e := os.ReadFile(path)
			if e != nil {
				return nil, e
			}
			var obj map[string]any
			if e = json.Unmarshal(b, &obj); e != nil {
				return nil, e
			}
			obj["userChanged"] = true
			b, e = json.Marshal(obj)
			if e == nil {
				e = os.WriteFile(path, b, 0600)
			}
			return nil, e
		})
		if e != nil {
			t.Fatal(e)
		}
		statement = "SELECT " + name + "();"
	}
	_, e = db.Exec(fmt.Sprintf("CREATE TRIGGER fail_finish BEFORE UPDATE ON routes WHEN NEW.status=3 BEGIN %s SELECT RAISE(FAIL,'synthetic finish failure'); END", statement))
	if e != nil {
		t.Fatal(e)
	}
	if interfere {
		m.Store.Close()
		m.Store, e = state.Open(filepath.Join(filepath.Dir(m.BackupRoot), "state.db"), fixtureProtector{})
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { m.Store.Close() })
	}
}

func TestFinishFailureRestoresFileAndRouteWhenStillOwned(t *testing.T) {
	m, p := fixtureManager(t)
	path := configPath(p, "claude")
	original := `{"env":{"ANTHROPIC_BASE_URL":"https://upstream.example"}}`
	writeFixture(t, path, original)
	finishFailure(t, m, path, false)
	if _, e := m.Reconcile(context.Background(), []Profile{p}); e == nil {
		t.Fatal("finish failure was hidden")
	}
	b, _ := os.ReadFile(path)
	routes, _ := m.Store.ListRoutes(context.Background())
	if string(b) != original || len(routes) != 0 {
		t.Fatal("safe rollback did not restore old state")
	}
}

func TestFailedRollbackRetainsOriginForUserEditedLocalURL(t *testing.T) {
	m, p := fixtureManager(t)
	path := configPath(p, "claude")
	writeFixture(t, path, `{"env":{"ANTHROPIC_BASE_URL":"https://upstream.example"}}`)
	finishFailure(t, m, path, true)
	if _, e := m.Reconcile(context.Background(), []Profile{p}); e == nil {
		t.Fatal("finish/rollback failure was hidden")
	}
	routes, _ := m.Store.ListRoutes(context.Background())
	if len(routes) != 1 || routes[0].Status != 1 {
		t.Fatal("recovery origin must remain Pending")
	}
	b, _ := os.ReadFile(path)
	var obj map[string]any
	_ = json.Unmarshal(b, &obj)
	if obj["userChanged"] != true || obj["env"].(map[string]any)["ANTHROPIC_BASE_URL"] != routes[0].InjectedBaseURL {
		t.Fatal("user edit or route reference was lost")
	}
}

func TestMalformedInactiveProviderDoesNotBlockCurrentProvider(t *testing.T) {
	m, p := fixtureManager(t)
	path := installCCFixture(t, p)
	writeFixture(t, configPath(p, "claude"), `{"env":{"ANTHROPIC_BASE_URL":"https://upstream.example"}}`)
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	_, e = db.Exec(`INSERT INTO providers VALUES('broken','claude','Fixture','not JSON',0)`)
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	rs, e := m.Reconcile(context.Background(), []Profile{p})
	if e != nil {
		t.Fatal(e)
	}
	unsupported := false
	for _, r := range rs {
		if r.ProviderID == "claude:broken" {
			unsupported = r.Status == 5
		}
	}
	if !unsupported {
		t.Fatal("unsupported provider was not reported")
	}
	routes, _ := m.Store.ListRoutes(context.Background())
	if len(routes) != 2 {
		t.Fatal("supported mappings not attached")
	}
}

package state

import (
	"context"
	"endpointai/client/internal/contracts"
	"endpointai/client/internal/protect"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countedProtector struct {
	Protector
	decrypts atomic.Int64
}

func (p *countedProtector) Unprotect(value []byte) (string, error) {
	p.decrypts.Add(1)
	return p.Protector.Unprotect(value)
}

func routeFixture() contracts.Route {
	now := time.Now().UTC()
	return contracts.Route{RouteID: "fixture-route", UserSID: "fixture-user", AgentType: 8, ProviderID: "fixture", OriginalBaseURL: "https://synthetic.invalid/v1", InjectedBaseURL: "http://127.0.0.1:18080/r/fixture-route", Status: 3, CreatedAtUTC: now, UpdatedAtUTC: now}
}

func TestRouteSnapshotReadsCopyWithoutSQLiteOrDecryption(t *testing.T) {
	dir := t.TempDir()
	key, e := protect.NewFileKey(filepath.Join(dir, "key"))
	if e != nil {
		t.Fatal(e)
	}
	p := &countedProtector{Protector: key}
	s, e := Open(filepath.Join(dir, "state.db"), p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := context.Background()
	r := routeFixture()
	if e = s.UpsertRoute(ctx, r); e != nil {
		t.Fatal(e)
	}
	decrypts := p.decrypts.Load()
	// Occupy the single SQLite connection. Forwarding must use the snapshot.
	conn, e := s.db.Conn(ctx)
	if e != nil {
		t.Fatal(e)
	}
	readCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	got, e := s.FindRoute(readCtx, r.RouteID)
	conn.Close()
	if e != nil || got == nil {
		t.Fatal(got, e)
	}
	got.OriginalBaseURL = "https://mutated.invalid"
	got.UserSID = "mutated"
	for i := 0; i < 100; i++ {
		got, e = s.FindRoute(ctx, r.RouteID)
		if e != nil || got.OriginalBaseURL != r.OriginalBaseURL || got.UserSID != r.UserSID {
			t.Fatal(got, e)
		}
	}
	if p.decrypts.Load() != decrypts {
		t.Fatal("hot route reads decrypted state")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = s.FindRoute(ctx, r.RouteID); e == nil {
		t.Fatal("closed store still served cached route")
	}
	s, e = Open(filepath.Join(dir, "state.db"), p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	got, e = s.FindRoute(ctx, r.RouteID)
	if e != nil || got.OriginalBaseURL != r.OriginalBaseURL {
		t.Fatal("restart did not restore decrypted route snapshot", e)
	}
}

func TestRouteSnapshotPublishesOnlyCommittedChangesAndKeepsDatabaseSemantics(t *testing.T) {
	dir := t.TempDir()
	key, e := protect.NewFileKey(filepath.Join(dir, "key"))
	if e != nil {
		t.Fatal(e)
	}
	s, e := Open(filepath.Join(dir, "state.db"), key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := context.Background()
	r := routeFixture()
	if e = s.UpsertRoute(ctx, r); e != nil {
		t.Fatal(e)
	}
	original, _ := s.FindRoute(ctx, r.RouteID)
	if _, e = s.db.Exec(`CREATE TRIGGER fail_route_update BEFORE UPDATE ON routes BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
		t.Fatal(e)
	}
	r.OriginalBaseURL = "https://replacement.invalid"
	if e = s.UpsertRoute(ctx, r); e == nil {
		t.Fatal("fixture update accepted")
	}
	got, _ := s.FindRoute(ctx, r.RouteID)
	if !reflect.DeepEqual(got, original) {
		t.Fatal("failed write published a snapshot")
	}
	s.db.Exec("DROP TRIGGER fail_route_update")
	r.CreatedAtUTC = r.CreatedAtUTC.Add(time.Hour)
	r.UpdatedAtUTC = r.UpdatedAtUTC.Add(time.Minute)
	if e = s.UpsertRoute(ctx, r); e != nil {
		t.Fatal(e)
	}
	got, _ = s.FindRoute(ctx, r.RouteID)
	stored, e := s.readRoute(s.db.QueryRowContext(ctx, "SELECT "+routeColumns+" FROM routes WHERE route_id=?", r.RouteID))
	if e != nil || !reflect.DeepEqual(got, stored) || !got.CreatedAtUTC.Equal(original.CreatedAtUTC) {
		t.Fatal("snapshot differed from committed route", got, stored, e)
	}
	if _, e = s.db.Exec(`CREATE TRIGGER fail_route_delete BEFORE DELETE ON routes BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
		t.Fatal(e)
	}
	if e = s.DeleteRoute(ctx, r.RouteID); e == nil {
		t.Fatal("fixture delete accepted")
	}
	if got, _ = s.FindRoute(ctx, r.RouteID); got == nil {
		t.Fatal("failed delete removed cached route")
	}
	s.db.Exec("DROP TRIGGER fail_route_delete")
	if e = s.DeleteRoute(ctx, r.RouteID); e != nil {
		t.Fatal(e)
	}
	if got, e = s.FindRoute(ctx, r.RouteID); e != nil || got != nil {
		t.Fatal("successful deletion not immediately visible", got, e)
	}
}

func TestReadOnlyRouteStoreRemainsLiveAndConcurrentSnapshotsAreSafe(t *testing.T) {
	dir := t.TempDir()
	key, e := protect.NewFileKey(filepath.Join(dir, "key"))
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "state.db")
	s, e := Open(path, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := context.Background()
	r := routeFixture()
	s.UpsertRoute(ctx, r)
	ro, e := OpenReadOnly(path, key)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	if ro.routes.Load() != nil {
		t.Fatal("read-only store cached live state")
	}
	r.OriginalBaseURL = "https://updated.invalid/v1"
	if e = s.UpsertRoute(ctx, r); e != nil {
		t.Fatal(e)
	}
	got, e := ro.FindRoute(ctx, r.RouteID)
	if e != nil || got.OriginalBaseURL != r.OriginalBaseURL {
		t.Fatal("read-only reader served stale snapshot", e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if _, e := s.FindRoute(ctx, r.RouteID); e != nil {
					t.Error(e)
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		if e = s.DeleteRoute(ctx, r.RouteID); e != nil {
			t.Fatal(e)
		}
		if e = s.UpsertRoute(ctx, r); e != nil {
			t.Fatal(e)
		}
	}
	wg.Wait()
}

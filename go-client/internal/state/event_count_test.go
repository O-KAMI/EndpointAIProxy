package state

import (
	"context"
	"endpointai/client/internal/contracts"
	"endpointai/client/internal/protect"
	"path/filepath"
	"testing"
)

func TestPendingEventCountBoundedAndPayloadIndependent(t *testing.T) {
	dir := t.TempDir()
	p, err := protect.NewFileKey(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(filepath.Join(dir, "state.db"), p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if n, err := s.PendingEventCount(ctx); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	if _, err = s.EnqueueEvent(ctx, contracts.EndpointEvent{EventID: "synthetic-event"}); err != nil {
		t.Fatal(err)
	}
	if n, err := s.PendingEventCount(ctx); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if _, err = s.db.Exec("UPDATE pending_control_events SET event_json='not-json'"); err != nil {
		t.Fatal(err)
	}
	if n, err := s.PendingEventCount(ctx); err != nil || n != 1 {
		t.Fatal("count decoded private event payload", n, err)
	}
	// A count query does not read or decode private event bodies. A damaged
	// over-limit table must not produce a plausible zero-depth health metric.
	if _, err = s.db.Exec(`WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<1005)
		INSERT INTO pending_control_events SELECT printf('synthetic-%d',n),'not-json' FROM seq`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PendingEventCount(ctx); err == nil {
		t.Fatal("over-limit state accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = s.PendingEventCount(cancelled); err == nil {
		t.Fatal("cancelled queue query accepted")
	}
}

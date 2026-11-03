package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"endpointai/client/internal/contracts"
	"endpointai/client/internal/protect"
	"endpointai/client/internal/state"
	"github.com/google/uuid"
)

func TestHealthReportsMergedPersistentAndVolatileBacklog(t *testing.T) {
	f := newFakeControl(t)
	base := newControlApp(t, f)
	dir := t.TempDir()
	p, err := protect.NewFileKey(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	store, err := state.Open(path, p)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	var first contracts.EndpointEvent
	for i := 0; i < 1000; i++ {
		event := contracts.EndpointEvent{EventID: uuid.NewString(), OccurredAtUTC: time.Now().UTC(), Severity: contracts.EventSeverityWarning, Type: "client", Code: "SYNTHETIC", Summary: "synthetic-private-event"}
		if i == 0 {
			first = event
		}
		if _, err = store.EnqueueEvent(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Fail startup restore and new persistence independently, retaining both
	// an old durable queue and the bounded in-memory fallback.
	if _, err = db.Exec("UPDATE pending_control_events SET event_json='invalid' WHERE event_id=?", first.EventID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`CREATE TRIGGER reject_event_write BEFORE INSERT ON pending_control_events BEGIN SELECT RAISE(ABORT,'synthetic'); END`); err != nil {
		t.Fatal(err)
	}
	opts := base.Options
	opts.DataRoot = dir
	a, err := New(ctx, opts, store, base.Audit, base.Profiles)
	if err != nil {
		t.Fatal(err)
	}
	if a.eventsLoaded {
		t.Fatal("damaged startup queue accepted")
	}
	for i := 0; i < 1000; i++ {
		a.AddEvent("SYNTHETIC", "synthetic-private-event")
	}
	data, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE pending_control_events SET event_json=? WHERE event_id=?", string(data), first.EventID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("DROP TRIGGER reject_event_write"); err != nil {
		t.Fatal(err)
	}
	if err = a.restorePendingEvents(ctx); err != nil {
		t.Fatal(err)
	}
	queue := eventQueueHealth(t, a, 200)
	if queue.MemoryDepth != 2000 || queue.PersistedDepth == nil || *queue.PersistedDepth != 1000 || !queue.MemoryBaselineLoaded || queue.Capacity != 1000 {
		t.Fatal("merged backlog hidden", queue)
	}
	for i := 0; i < 20; i++ {
		if err = a.Sync(ctx); err != nil {
			t.Fatal(err)
		}
	}
	queue = eventQueueHealth(t, a, 200)
	if queue.MemoryDepth != 0 || queue.PersistedDepth == nil || *queue.PersistedDepth != 0 {
		t.Fatal("backlog did not drain", queue)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.counts["events"] != 20 {
		t.Fatal("recovery did not use bounded event batches", f.counts["events"])
	}
	seen := make(map[string]bool)
	for _, id := range f.eventIDs {
		if seen[id] {
			t.Fatal("recovery duplicated an event")
		}
		seen[id] = true
	}
	if len(seen) != 2000 {
		t.Fatal("recovery lost event identities", len(seen))
	}
}

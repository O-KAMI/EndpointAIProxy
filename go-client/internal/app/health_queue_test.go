package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"endpointai/client/internal/protect"
	"endpointai/client/internal/state"
)

type eventQueueHealthSnapshot struct {
	MemoryDepth          int    `json:"memoryDepth"`
	MemoryBaselineLoaded bool   `json:"memoryBaselineLoaded"`
	Capacity             int    `json:"capacity"`
	PersistedDepth       *int   `json:"persistedDepth"`
	PersistedReadStatus  string `json:"persistedReadStatus"`
}

func eventQueueHealth(t *testing.T, a *App, expectedStatus int) eventQueueHealthSnapshot {
	t.Helper()
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != expectedStatus {
		t.Fatalf("health status %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "synthetic-private-event") || strings.Contains(w.Body.String(), "pending_control_events") {
		t.Fatal("health leaked event or database error")
	}
	var result struct {
		ControlEventQueue eventQueueHealthSnapshot `json:"controlEventQueue"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result.ControlEventQueue
}

func TestHealthEventQueueSurvivesRestartAndClearsAfterAcknowledgment(t *testing.T) {
	a := newControlApp(t, newFakeControl(t))
	assertDepth := func(app *App, expected int) {
		t.Helper()
		queue := eventQueueHealth(t, app, 200)
		if queue.MemoryDepth != expected || queue.PersistedDepth == nil || *queue.PersistedDepth != expected || !queue.MemoryBaselineLoaded || queue.Capacity != 1000 || queue.PersistedReadStatus != "available" {
			t.Fatal("incorrect queue snapshot", queue)
		}
	}
	assertDepth(a, 0)
	a.AddEvent("SYNTHETIC", "synthetic-private-event")
	assertDepth(a, 1)
	if err := a.Store.Close(); err != nil {
		t.Fatal(err)
	}
	p, err := protect.NewFileKey(filepath.Join(a.Options.DataRoot, "key"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(filepath.Join(a.Options.DataRoot, "state.db"), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	resumed, err := New(context.Background(), a.Options, store, a.Audit, a.Profiles)
	if err != nil {
		t.Fatal(err)
	}
	assertDepth(resumed, 1)
	if err = resumed.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertDepth(resumed, 0)
}

func TestHealthEventQueueUnavailableIsUnknownRatherThanZero(t *testing.T) {
	a := newControlApp(t, newFakeControl(t))
	a.AddEvent("SYNTHETIC", "synthetic-private-event")
	db, err := sql.Open("sqlite", filepath.Join(a.Options.DataRoot, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec("DROP TABLE pending_control_events"); err != nil {
		t.Fatal(err)
	}
	queue := eventQueueHealth(t, a, 503)
	if queue.MemoryDepth != 1 || queue.PersistedDepth != nil || queue.PersistedReadStatus != "unavailable" {
		t.Fatal("failed read disguised as an empty queue", queue)
	}
}

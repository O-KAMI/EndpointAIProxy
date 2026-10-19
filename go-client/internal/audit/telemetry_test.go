package audit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func logRecords(t *testing.T, s *Store) []map[string]any {
	t.Helper()
	paths, _ := filepath.Glob(filepath.Join(s.Root, "logs", "service", "*.jsonl"))
	var rows []map[string]any
	for _, p := range paths {
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			var row map[string]any
			if json.Unmarshal([]byte(line), &row) == nil {
				rows = append(rows, row)
			}
		}
	}
	return rows
}
func TestDiagnosticFailureDomainsAndSecretRemoval(t *testing.T) {
	s := New(t.TempDir())
	t.Cleanup(s.CloseLogs)
	s.captureFailure("capture_sync", &os.PathError{Op: "sync", Path: "secret-path-token", Err: syscall.ENOSPC})
	v := s.Snapshot()
	if !s.Degraded() || v.AuditFailureCount != 1 || v.LastAuditFailure.ErrorClass != "DISK_FULL" || v.LastAuditFailure.OSCode == 0 {
		t.Fatal(v)
	}
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "secret") {
		t.Fatal(string(b))
	}
	other := New(t.TempDir())
	t.Cleanup(other.CloseLogs)
	os.WriteFile(filepath.Join(other.Root, "logs"), []byte("fixture"), 0600)
	other.Log("SERVICE_STARTED", map[string]any{"stage": "startup", "failed": true, "version": "0.2.0", "runId": "10000000-0000-0000-0000-000000000001", "secret": "token", "payload": strings.Repeat("secret", 100000)})
	other.CloseLogs()
	if other.Degraded() || other.Snapshot().LogWriteFailureCount == 0 {
		t.Fatal(other.Snapshot())
	}
	fields := sanitizeLogFields(map[string]any{"failed": true, "changed": false, "version": "0.2.0", "runId": "10000000-0000-0000-0000-000000000001", "errorClass": errors.New("secret"), "stage": "/private/path"})
	if fields["failed"] != true || fields["version"] != "0.2.0" || fields["runId"] == nil || fields["stage"] != nil || fields["errorClass"] != nil {
		t.Fatal(fields)
	}
}
func TestSuccessfulRequestsAggregateAndFailuresHaveBoundedStatistics(t *testing.T) {
	s := New(t.TempDir())
	t.Cleanup(s.CloseLogs)
	for i := 0; i < 100; i++ {
		s.Log("REQUEST_COMPLETED", map[string]any{"status": 200, "outcome": "SUCCESS", "durationMilliseconds": int64(2), "captureFinalizeMilliseconds": float64(1.5)})
	}
	for i := 0; i < 20; i++ {
		s.Log("REQUEST_FAILED", map[string]any{"stage": "upstream", "errorClass": "TIMEOUT"})
	}
	s.CloseLogs()
	if s.Snapshot().LogSuppressedCount != 19 || s.Degraded() {
		t.Fatal(s.Snapshot())
	}
	var aggregated, suppressed bool
	for _, r := range logRecords(t, s) {
		switch r["Code"] {
		case "LOG_MINUTE_SUMMARY":
			aggregated = r["SuccessfulRequestCount"] == float64(100) && r["CaptureFinalizeSumMilliseconds"] == float64(150)
		case "LOG_FAILURES_SUPPRESSED":
			suppressed = r["SuppressedCount"] == float64(19) && r["FirstAtUtc"] != nil && r["LastAtUtc"] != nil
		}
	}
	if !aggregated || !suppressed {
		t.Fatal(logRecords(t, s))
	}
}
func TestLoggerIndependentOfCompressionWorker(t *testing.T) {
	s := New(t.TempDir())
	t.Cleanup(s.CloseLogs)
	s.compressionMu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	// Occupy maintenance compression while a lifecycle record must still persist.
	p := filepath.Join(s.Root, "captures", "fixture.md")
	os.MkdirAll(filepath.Dir(p), 0700)
	os.WriteFile(p, []byte("fixture"), 0600)
	s.queue <- p
	s.Log("SERVICE_STARTED", nil)
	deadline := time.Now().Add(time.Second)
	for len(logRecords(t, s)) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	persisted := len(logRecords(t, s)) > 0
	cancel()
	s.compressionMu.Unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("workers did not join")
	}
	if !persisted {
		t.Fatal("logger stalled behind compression")
	}
}
func BenchmarkSuccessfulRequestObservation(b *testing.B) {
	s := New(b.TempDir())
	fields := map[string]any{"status": 200, "outcome": "SUCCESS", "durationMilliseconds": int64(1), "captureFinalizeMilliseconds": float64(1)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Log("REQUEST_COMPLETED", fields)
	}
}

func TestDiagnosticIdentifierHashIsIdempotent(t *testing.T) {
	first := sanitizeLogFields(map[string]any{"routeId": "legacy-route-fixture"})["routeId"]
	second := sanitizeLogFields(map[string]any{"routeId": first})["routeId"]
	if first != second || !strings.HasPrefix(first.(string), "sha256:") {
		t.Fatal(first, second)
	}
}

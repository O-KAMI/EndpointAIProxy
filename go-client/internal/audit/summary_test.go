package audit

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Force compression to queue before append. The former append opened its file
// before taking summaryMu and silently wrote into an unlinked descriptor.
func TestSummaryAppendCompressionLifecycle(t *testing.T) {
	s := New(t.TempDir())
	t.Cleanup(s.CloseLogs)
	path := filepath.Join(s.Root, "captures", "summary", "2000-01-01.jsonl")
	os.MkdirAll(filepath.Dir(path), 0700)
	os.WriteFile(path, []byte("{\"old\":true}\n"), 0600)
	s.summaryMu.Lock()
	compressed, appended := make(chan error, 1), make(chan error, 1)
	go func() { compressed <- s.compress(path) }()
	waitForWorker := func(name string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			stack := make([]byte, 1<<20)
			n := runtime.Stack(stack, true)
			if strings.Contains(string(stack[:n]), name) {
				return
			}
			time.Sleep(time.Millisecond)
		}
		s.summaryMu.Unlock()
		t.Fatal("worker did not reach file lifecycle lock")
	}
	waitForWorker("(*Store).compress")
	go func() { appended <- s.append(path, map[string]bool{"late": true}) }()
	waitForWorker("(*Store).append")
	s.summaryMu.Unlock()
	if e := <-compressed; e != nil {
		t.Fatal(e)
	}
	if e := <-appended; e != nil {
		t.Fatal(e)
	}
	all := ""
	if data, e := os.ReadFile(path); e == nil {
		all += string(data)
	}
	if f, e := os.Open(path + ".gz"); e == nil {
		z, e := gzip.NewReader(f)
		if e != nil {
			f.Close()
			t.Fatal(e)
		}
		data, e := io.ReadAll(z)
		z.Close()
		f.Close()
		if e != nil {
			t.Fatal(e)
		}
		all += string(data)
	}
	if strings.Count(all, "\"late\"") != 1 || strings.Count(all, "\"old\"") != 1 {
		t.Fatal("summary lost or duplicated despite successful append", all)
	}
}

func TestCrossDayActiveCaptureProtectsSummaryUntilCompletion(t *testing.T) {
	s := New(t.TempDir())
	t.Cleanup(s.CloseLogs)
	now := time.Now().UTC()
	rec := fixtureRecord()
	rec.Started = now.Add(-8 * 24 * time.Hour)
	path := filepath.Join(s.Root, "captures", "summary", rec.Started.Format("2006-01-02")+".jsonl")
	auditFile(t, path, rec.Started)
	c := s.Start(rec).(*Session)
	s.Maintain(now)
	if _, e := os.Stat(path); e != nil {
		t.Fatal("active cross-day summary removed", e)
	}
	if e := s.compress(path); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(path); e != nil {
		t.Fatal("active cross-day summary compressed", e)
	}
	c.Body([]byte("late stream"))
	c.Complete("SUCCESS", 200, "", time.Second)
	if s.capturesInFlight.Load() != 0 || len(s.activeDays) != 0 {
		t.Fatal("capture activity leaked")
	}
	data, e := os.ReadFile(path)
	if e != nil || !strings.Contains(string(data), rec.RequestID) {
		t.Fatal("late capture summary absent", e)
	}
	if e = os.Chtimes(path, rec.Started, rec.Started); e != nil {
		t.Fatal(e)
	}
	s.Maintain(now)
	if _, e = os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("inactive expired summary retained", e)
	}
	if s.Degraded() {
		t.Fatal(s.Snapshot())
	}
}

func TestSummaryWritersAreBoundedWriteThroughAndClosed(t *testing.T) {
	s := New(t.TempDir())
	t.Cleanup(s.CloseLogs)
	for _, day := range []string{"2000-01-01", "2000-01-02", "2000-01-03", "2000-01-01"} {
		if e := s.append(filepath.Join(s.Root, "captures", "summary", day+".jsonl"), map[string]string{"fixture": day}); e != nil {
			t.Fatal(e)
		}
		if len(s.summaryWriters) > maximumSummaryWriters {
			t.Fatal("unbounded open summary descriptors")
		}
	}
	path := filepath.Join(s.Root, "captures", "summary", "2000-01-01.jsonl")
	data, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var row map[string]string
		if e = json.Unmarshal([]byte(line), &row); e != nil {
			t.Fatal("corrupt single-write JSONL", e)
		}
	}
	if strings.Count(string(data), "\n") != 2 {
		t.Fatal("record lost during handle eviction")
	}
	s.CloseLogs()
	if len(s.summaryWriters) != 0 {
		t.Fatal("open summary handle after shutdown")
	}
}

func TestCompressionDefersYoungCapturesAndBoundsBatch(t *testing.T) {
	s := New(t.TempDir())
	t.Cleanup(s.CloseLogs)
	now := time.Now().UTC()
	pending := map[string]bool{}
	for i := 0; i < compressionBatchFiles+2; i++ {
		path := filepath.Join(s.Root, "captures", string(rune('a'+i))+".md")
		auditFile(t, path, now)
		pending[path] = true
	}
	s.compressBatch(context.Background(), now, pending)
	if len(pending) != compressionBatchFiles+2 {
		t.Fatal("young captures compressed on request burst")
	}
	s.capturesInFlight.Add(1)
	s.compressBatch(context.Background(), now.Add(10*time.Second), pending)
	if len(pending) != compressionBatchFiles+2 {
		t.Fatal("compression competed with recent active traffic")
	}
	s.compressBatch(context.Background(), now.Add(2*time.Minute), pending)
	if len(pending) != compressionBatchFiles+1 {
		t.Fatal("busy recovery must make bounded one-file progress")
	}
	s.capturesInFlight.Add(-1)
	s.compressBatch(context.Background(), now.Add(2*time.Minute), pending)
	if len(pending) < 1 {
		t.Fatal("compression exceeded batch file budget")
	}
}

func TestPerformanceSamplesAreOptInBoundedAndSafe(t *testing.T) {
	s := New(t.TempDir())
	t.Cleanup(s.CloseLogs)
	samples := make(chan PerformanceSample, 1)
	s.PerformanceSamples = samples
	c := s.Start(fixtureRecord())
	c.Body([]byte("sensitive fixture only in capture"))
	c.Complete("SUCCESS", 200, "", time.Millisecond)
	if len(samples) != 1 {
		t.Fatal("profiling channel is not bounded")
	}
	sample := <-samples
	if sample.Stage != "capture_create" || sample.Duration < 0 {
		t.Fatal(sample)
	}
	if s.Degraded() {
		t.Fatal("profiling queue overflow changed capture reliability")
	}
}

func TestCaptureCreationFailureReleasesActivityAndSummaryWriteFailureDegrades(t *testing.T) {
	bad := New(filepath.Join(t.TempDir(), "not-directory"))
	t.Cleanup(bad.CloseLogs)
	if e := os.WriteFile(bad.Root, []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if c := bad.Start(fixtureRecord()); c != nil {
		t.Fatal("capture unexpectedly started")
	}
	if bad.capturesInFlight.Load() != 0 || len(bad.activeDays) != 0 {
		t.Fatal("failed start leaked active capture")
	}
	s := New(t.TempDir())
	t.Cleanup(s.CloseLogs)
	rec := fixtureRecord()
	path := filepath.Join(s.Root, "captures", "summary", rec.Started.Format("2006-01-02")+".jsonl")
	if e := s.append(path, map[string]bool{"fixture": true}); e != nil {
		t.Fatal(e)
	}
	if e := s.summaryWriters[path].file.Close(); e != nil {
		t.Fatal(e)
	}
	c := s.Start(rec)
	c.Body([]byte("fixture"))
	c.Complete("SUCCESS", 200, "", time.Millisecond)
	if !s.Degraded() || s.Snapshot().LastAuditFailure.Stage != "summary_append" {
		t.Fatal("summary write error was not observable", s.Snapshot())
	}
	if s.capturesInFlight.Load() != 0 || len(s.activeDays) != 0 {
		t.Fatal("failed summary leaked activity")
	}
}

func TestCompressionRecoversCrashTemporaryAndLostQueueHints(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "captures", "fixture.md")
	auditFile(t, path, time.Now().Add(-time.Minute))
	if e := os.WriteFile(path+".gz.tmp", []byte("incomplete gzip"), 0600); e != nil {
		t.Fatal(e)
	}
	// A fresh Store has no in-memory queue, but scanning reconstructs it.
	s := New(root)
	t.Cleanup(s.CloseLogs)
	s.Maintain(time.Now().UTC())
	if len(s.queue) == 0 {
		t.Fatal("restart scan did not recover disk backlog")
	}
	pending := map[string]bool{}
	for len(s.queue) != 0 {
		pending[<-s.queue] = true
	}
	s.compressBatch(context.Background(), time.Now().UTC(), pending)
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("durable raw input was not compressed after restart", e)
	}
	f, e := os.Open(path + ".gz")
	if e != nil {
		t.Fatal(e)
	}
	z, e := gzip.NewReader(f)
	if e != nil {
		f.Close()
		t.Fatal(e)
	}
	data, e := io.ReadAll(z)
	z.Close()
	f.Close()
	if e != nil || string(data) != "fixture" {
		t.Fatal("crashed temporary was published", e)
	}
	if s.Degraded() {
		t.Fatal(s.Snapshot())
	}
}

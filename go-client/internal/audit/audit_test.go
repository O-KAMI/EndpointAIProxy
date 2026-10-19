package audit

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"endpointai/client/internal/contracts"
	"endpointai/client/internal/proxy"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConcurrentCompletionPreservesSummaryRecords(t *testing.T) {
	s := New(t.TempDir())
	t.Cleanup(s.CloseLogs)
	const count = 32
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := fixtureRecord()
			r.RequestID = proxy.UUID()
			c := s.Start(r)
			if c == nil {
				t.Error("capture unavailable")
				return
			}
			c.Body([]byte("buffered fixture"))
			c.Complete("SUCCESS", 200, "", time.Millisecond)
		}()
	}
	wg.Wait()
	paths, e := filepath.Glob(filepath.Join(s.Root, "captures", "summary", "*.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	seen := make(map[string]bool)
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var record struct{ RequestId, MarkdownPath string }
			if err = json.Unmarshal(scanner.Bytes(), &record); err != nil {
				t.Fatal("interleaved JSON record", err)
			}
			if seen[record.RequestId] {
				t.Fatal("duplicate completion")
			}
			seen[record.RequestId] = true
			body, err := os.ReadFile(record.MarkdownPath)
			if err != nil || !strings.Contains(string(body), "buffered fixture") {
				t.Fatal("completed record references incomplete evidence", err)
			}
		}
		err = scanner.Err()
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != count || s.Degraded() {
		t.Fatal("lost or degraded capture", len(seen))
	}
}

func fixtureRecord() proxy.Record {
	return proxy.Record{RequestID: "fixture-request", Started: time.Now().UTC(), Route: contracts.Route{RouteID: "abcdefghijklmnopqrstuv", UserSID: "fixture-user", ProviderID: "direct", OriginalBaseURL: "https://origin.example?api_key=url-secret"}, UserID: "fixture", Agent: "Codex", Surface: "cli", Inbound: "/r/fixture/responses?token=inbound-secret", Outbound: "https://origin.example/v1/responses?key=outbound-secret"}
}
func TestCaptureCombinedLimitHashesRedactionAndSummary(t *testing.T) {
	s := New(t.TempDir())
	t.Cleanup(s.CloseLogs)
	s.BodyLimit = 10
	rec := fixtureRecord()
	capture := s.Start(rec)
	if capture == nil {
		t.Fatal("capture unavailable")
	}
	session := capture.(*Session)
	request := []byte("REQ12345")
	response := []byte("RESP67890")
	capture.Headers("Inbound", http.Header{"Authorization": {"Bearer auth-secret"}, "Cookie": {"cookie-secret"}, "X-Api-Key": {"api-secret"}, "X-Fixture": {"retain"}})
	capture.Request(request)
	capture.Response(200, http.Header{"Set-Cookie": {"response-cookie-secret"}})
	capture.Body(response)
	capture.Complete("SUCCESS", 200, "", 1250*time.Millisecond)
	b, e := os.ReadFile(session.complete)
	if e != nil {
		t.Fatal(e)
	}
	text := string(b)
	if session.captured != 10 || !strings.Contains(text, "REQ12345") || strings.Contains(text, "RESP67890") {
		t.Fatal("combined cap not enforced")
	}
	for _, secret := range []string{"auth-secret", "cookie-secret", "api-secret", "response-cookie-secret", "url-secret", "inbound-secret", "outbound-secret"} {
		if strings.Contains(text, secret) {
			t.Fatal("secret captured", secret)
		}
	}
	for _, body := range [][]byte{request, response} {
		sum := sha256.Sum256(body)
		if !strings.Contains(text, hex.EncodeToString(sum[:])) {
			t.Fatal("full-body hash missing")
		}
	}
	summaryPath := filepath.Join(s.Root, "captures", "summary", rec.Started.Format("2006-01-02")+".jsonl")
	b, e = os.ReadFile(summaryPath)
	if e != nil {
		t.Fatal(e)
	}
	var summary map[string]any
	if e = json.Unmarshal(b, &summary); e != nil {
		t.Fatal(e)
	}
	if summary["RequestBytes"] != float64(8) || summary["ResponseBytes"] != float64(9) || summary["CaptureTruncated"] != true || summary["StatusCode"] != float64(200) || summary["DurationMilliseconds"] != float64(1250) || summary["Outcome"] != "SUCCESS" {
		t.Fatal("summary metadata incorrect", summary)
	}
	if strings.Contains(string(b), "url-secret") || strings.Contains(string(b), "inbound-secret") || strings.Contains(string(b), "outbound-secret") {
		t.Fatal("summary URL not redacted")
	}
}
func TestCompletedCaptureGzipIsReadableAndIdempotent(t *testing.T) {
	s := New(t.TempDir())
	t.Cleanup(s.CloseLogs)
	c := s.Start(fixtureRecord()).(*Session)
	c.Request([]byte("request fixture"))
	c.Response(200, nil)
	c.Body([]byte("response fixture"))
	c.Complete("SUCCESS", 200, "", time.Millisecond)
	want, e := os.ReadFile(c.complete)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.compress(c.complete); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(c.complete); !os.IsNotExist(e) {
		t.Fatal("uncompressed file retained")
	}
	f, e := os.Open(c.complete + ".gz")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	got, e := io.ReadAll(z)
	if e != nil || string(got) != string(want) {
		t.Fatal("gzip unreadable or corrupt", e)
	}
	if e = s.compress(c.complete); e != nil {
		t.Fatal("repeat compression not idempotent", e)
	}
}
func auditFile(t *testing.T, path string, age time.Time) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chtimes(path, age, age); e != nil {
		t.Fatal(e)
	}
}
func TestMaintenanceDeletesExpiredButPreservesActiveAndSymlinks(t *testing.T) {
	s := New(t.TempDir())
	t.Cleanup(s.CloseLogs)
	now := time.Now().UTC()
	old := now.Add(-8 * 24 * time.Hour)
	expired := filepath.Join(s.Root, "captures", "fixture", "expired.md")
	active := filepath.Join(s.Root, "captures", "fixture", "active.partial")
	recent := filepath.Join(s.Root, "captures", "fixture", "recent.md")
	auditFile(t, expired, old)
	auditFile(t, active, old)
	auditFile(t, recent, now)
	s.active[active] = true
	outside := filepath.Join(t.TempDir(), "outside.md")
	auditFile(t, outside, old)
	link := filepath.Join(s.Root, "captures", "fixture", "linked.md")
	if e := os.Symlink(outside, link); e != nil {
		t.Skip("symlink unavailable")
	}
	outsideDir := t.TempDir()
	nested := filepath.Join(outsideDir, "nested.md")
	auditFile(t, nested, old)
	dirLink := filepath.Join(s.Root, "captures", "linked-dir")
	if e := os.Symlink(outsideDir, dirLink); e != nil {
		t.Fatal(e)
	}
	s.Maintain(now)
	if _, e := os.Stat(expired); !os.IsNotExist(e) {
		t.Fatal("expired capture retained")
	}
	for _, path := range []string{active, recent, outside, nested} {
		if _, e := os.Stat(path); e != nil {
			t.Fatal("protected file removed", path, e)
		}
	}
	if info, e := os.Lstat(link); e != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink changed")
	}
	if e := s.compress(link); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Lstat(link + ".gz"); !os.IsNotExist(e) {
		t.Fatal("compression followed symlink")
	}
}
func TestOperationalLogsDropCredentialFields(t *testing.T) {
	s := New(t.TempDir())
	t.Cleanup(s.CloseLogs)
	s.Log("FIXTURE", map[string]any{"authorization": "secret-auth", "cookie": "secret-cookie", "api_key": "secret-key", "stage": "retained"})
	s.CloseLogs()
	paths, e := filepath.Glob(filepath.Join(s.Root, "logs", "service", "*.jsonl"))
	if e != nil || len(paths) != 1 {
		t.Fatal(paths, e)
	}
	b, e := os.ReadFile(paths[0])
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(b), "secret-") || !strings.Contains(string(b), "retained") {
		t.Fatal("log redaction incorrect")
	}
}

func TestLogRotationPreservesEventsAndMaintenanceSkipsOpenShard(t *testing.T) {
	s := New(t.TempDir())
	t.Cleanup(s.CloseLogs)
	s.LogFileLimit = 100
	t.Cleanup(s.CloseLogs)
	for i := 0; i < 6; i++ {
		s.Log("FIXTURE", map[string]any{"stage": strings.Repeat("x", 100), "count": i})
	}
	s.FlushLogs()
	paths, e := filepath.Glob(filepath.Join(s.Root, "logs", "service", "*.jsonl"))
	if e != nil || len(paths) != 6 {
		t.Fatal("rotation did not split events", paths, e)
	}
	count := 0
	for _, path := range paths {
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			var event map[string]any
			if e = json.Unmarshal([]byte(line), &event); e != nil {
				t.Fatal("corrupt rotated event", e)
			}
			count++
		}
	}
	if count != 6 {
		t.Fatal("events lost across rotation", count)
	}
	active := s.logPath
	now := time.Now().UTC()
	old := now.Add(-8 * 24 * time.Hour)
	for _, path := range paths {
		if e = os.Chtimes(path, old, old); e != nil {
			t.Fatal(e)
		}
	}
	s.Maintain(now)
	if _, e = os.Stat(active); e != nil {
		t.Fatal("open log shard deleted", e)
	}
	for _, path := range paths {
		if path != active {
			if _, e = os.Stat(path); !os.IsNotExist(e) {
				t.Fatal("expired closed shard retained", e)
			}
		}
	}
	s.CloseLogs()
	s.Maintain(now)
	if _, e = os.Stat(active); !os.IsNotExist(e) {
		t.Fatal("closed expired shard retained", e)
	}
}
func TestLogQueueOverflowIsBoundedAndNonBlocking(t *testing.T) {
	s := New(t.TempDir())
	t.Cleanup(s.CloseLogs)
	s.logQueue = make(chan map[string]any, 2)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			s.Log("FIXTURE", nil)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("logging blocked on full queue")
	}
	if len(s.logQueue) != 2 || s.dropped.Load() != 98 || s.Degraded() {
		t.Fatal("overflow not bounded or accounted", len(s.logQueue), s.dropped.Load())
	}
	s.CloseLogs()
	if len(s.logQueue) != 0 {
		t.Fatal("shutdown did not drain queue")
	}
}

func TestExactCombinedLimitIsNotTruncated(t *testing.T) {
	s := New(t.TempDir())
	t.Cleanup(s.CloseLogs)
	s.BodyLimit = 10
	rec := fixtureRecord()
	c := s.Start(rec).(*Session)
	c.Request([]byte("12345"))
	c.Response(200, nil)
	c.Body([]byte("67890"))
	c.Complete("SUCCESS", 200, "", time.Millisecond)
	b, e := os.ReadFile(filepath.Join(s.Root, "captures", "summary", rec.Started.Format("2006-01-02")+".jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	var summary map[string]any
	if e = json.Unmarshal(b, &summary); e != nil {
		t.Fatal(e)
	}
	if summary["CaptureTruncated"] != false {
		t.Fatal("exact-size capture incorrectly marked truncated")
	}
}

func TestMaintenanceEnforcesCaptureAndLogHighWaterWithSparseFixtures(t *testing.T) {
	now := time.Now().UTC()
	for _, tc := range []struct {
		name, dir, filename string
		size                int64
	}{{"capture", "captures", "oversize.md", 513 << 20}, {"service", filepath.Join("logs", "service"), "rotated-fixture.jsonl", 51 << 20}} {
		t.Run(tc.name, func(t *testing.T) {
			s := New(t.TempDir())
			t.Cleanup(s.CloseLogs)
			path := filepath.Join(s.Root, tc.dir, tc.filename)
			if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
				t.Fatal(e)
			}
			f, e := os.Create(path)
			if e != nil {
				t.Fatal(e)
			}
			e = f.Truncate(tc.size)
			f.Close()
			if e != nil {
				t.Fatal(e)
			}
			if e = os.Chtimes(path, now.Add(-time.Hour), now.Add(-time.Hour)); e != nil {
				t.Fatal(e)
			}
			s.Maintain(now)
			if _, e = os.Stat(path); !os.IsNotExist(e) {
				t.Fatal("high-water fixture not reclaimed", e)
			}
		})
	}
}

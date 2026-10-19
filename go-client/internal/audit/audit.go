// Package audit stores durable request captures and bounded asynchronous diagnostics.
package audit

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"endpointai/client/internal/observability"
	"endpointai/client/internal/proxy"
)

const DefaultBodyLimit int64 = 50 * 1024 * 1024

type Store struct {
	Root               string
	BodyLimit          int64
	mu                 sync.Mutex
	summaryMu          sync.Mutex
	summaryWriters     map[string]*summaryWriter
	summarySequence    uint64
	daysMu             sync.Mutex
	activeDays         map[string]int
	capturesInFlight   atomic.Int64
	PerformanceSamples chan<- PerformanceSample
	logMu              sync.Mutex
	compressionMu      sync.Mutex
	active             map[string]bool
	queue              chan string
	logQueue           chan map[string]any
	priorityQueue      chan map[string]any
	telemetryMu        sync.Mutex
	telemetry          DiagnosticsSnapshot
	statisticsMu       sync.Mutex
	statistics         map[string]int64
	rate               map[string]rateWindow
	suppressed         atomic.Int64
	writeFailures      atomic.Int64
	lastReportedDrops  int64
	logFile            *os.File
	logPath            string
	logBytes           int64
	LogFileLimit       int64
	dropped            atomic.Int64
	degraded           atomic.Bool
}

func New(root string) *Store {
	return &Store{Root: root, BodyLimit: DefaultBodyLimit, LogFileLimit: 20 << 20, active: make(map[string]bool), summaryWriters: make(map[string]*summaryWriter), activeDays: make(map[string]int), queue: make(chan string, 128), logQueue: make(chan map[string]any, 4096), priorityQueue: make(chan map[string]any, 256), statistics: make(map[string]int64), rate: make(map[string]rateWindow)}
}
func (s *Store) Degraded() bool { return s.degraded.Load() }
func safe(value string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == '/' || r == '\\' || r == ':' {
			return '_'
		}
		return r
	}, value)
}
func inline(value string) string {
	return strings.NewReplacer("`", "'", "\r", " ", "\n", " ").Replace(value)
}

func Sensitive(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "authorization") || strings.Contains(n, "token") || strings.Contains(n, "api-key") || strings.Contains(n, "apikey") || strings.Contains(n, "api_key") || strings.Contains(n, "secret") || strings.Contains(n, "signature") || n == "cookie" || n == "set-cookie" || n == "x-sf-ai-signature"
}
func RedactURL(value string) string {
	u, e := url.Parse(value)
	if e != nil {
		return "[invalid-url]"
	}
	if u.User != nil {
		u.User = url.User("[REDACTED]")
	}
	q := u.Query()
	for name := range q {
		if Sensitive(name) || strings.EqualFold(name, "key") {
			q.Set(name, "[REDACTED]")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

type Session struct {
	store                                              *Store
	record                                             proxy.Record
	mu                                                 sync.Mutex
	file                                               *os.File
	buffer                                             *bufio.Writer
	partial, complete                                  string
	requestHash, responseHash                          hash.Hash
	requestBytes, responseBytes, captured              int64
	requestStarted, responseStarted, completed, failed bool
	failure                                            observability.Detail
	timing                                             map[string]time.Time
}

func (s *Store) Start(rec proxy.Record) proxy.Capture {
	started := s.performanceStart()
	defer func() { s.performance("capture_create", started) }()
	day := rec.Started.UTC().Format("2006-01-02")
	s.daysMu.Lock()
	s.activeDays[day]++
	s.daysMu.Unlock()
	s.capturesInFlight.Add(1)
	startedCapture := false
	defer func() {
		if !startedCapture {
			s.releaseDay(day)
		}
	}()
	dir := filepath.Join(s.Root, "captures", safe(rec.Route.UserSID), rec.Started.Format("2006-01-02"))
	if e := os.MkdirAll(dir, 0700); e != nil {
		s.captureFailure("capture_create_directory", e)
		return nil
	}
	stem := rec.Started.Format("20060102T150405.000Z") + "_" + strings.ReplaceAll(rec.RequestID, "-", "")
	partial := filepath.Join(dir, stem+".partial")
	f, e := os.OpenFile(partial, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		s.captureFailure("capture_open", e)
		return nil
	}
	c := &Session{store: s, record: rec, file: f, partial: partial, complete: filepath.Join(dir, stem+".md"), requestHash: sha256.New(), responseHash: sha256.New(), timing: map[string]time.Time{"AgentRequestReceivedAtUtc": rec.Started}}
	c.buffer = bufio.NewWriterSize(f, 64*1024)
	s.mu.Lock()
	s.active[partial] = true
	s.mu.Unlock()
	c.write(fmt.Sprintf("# SF Endpoint AI Proxy Capture\n\n- Request ID: `%s`\n- Started UTC: `%s`\n- User ID: `%s`\n- User SID: `%s`\n- Agent: `%s`\n- Agent surface: `%s`\n- Provider: `%s`\n- Route: `%s`\n- Original BaseURL: `%s`\n- Inbound: `%s`\n- Outbound: `%s`\n\n", rec.RequestID, rec.Started.Format(time.RFC3339Nano), inline(rec.UserID), inline(rec.Route.UserSID), inline(rec.Agent), inline(rec.Surface), inline(rec.Route.ProviderID), rec.Route.RouteID, inline(RedactURL(rec.Route.OriginalBaseURL)), inline(RedactURL(rec.Inbound)), inline(RedactURL(rec.Outbound))))
	startedCapture = true
	return c
}

func (s *Session) write(value string) {
	if s.failed {
		return
	}
	if _, e := io.WriteString(s.buffer, value); e != nil {
		s.failed = true
		s.store.captureFailure("capture_write", e)
	}
}
func (s *Session) headers(headers http.Header) {
	s.write("``````http\n")
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range headers[name] {
			if Sensitive(name) {
				value = "[REDACTED]"
			}
			s.write(inline(name) + ": " + inline(value) + "\n")
		}
	}
	s.write("``````\n\n")
}
func (s *Session) Headers(title string, h http.Header) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return
	}
	s.write("## " + inline(title) + "\n\n")
	s.headers(h)
}
func (s *Session) Timing(stage string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.completed {
		s.timing[stage] = at
	}
}
func (s *Session) bytes(p []byte) {
	remaining := s.store.BodyLimit - s.captured
	if remaining <= 0 || s.failed {
		return
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, e := s.buffer.Write(p)
	s.captured += int64(n)
	if e != nil {
		s.failed = true
		s.store.captureFailure("capture_write", e)
	}
}
func (s *Session) Request(p []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return
	}
	if !s.requestStarted {
		s.requestStarted = true
		s.write("## Request body\n\n``````\n")
	}
	s.requestHash.Write(p)
	s.requestBytes += int64(len(p))
	s.bytes(p)
}
func (s *Session) Response(status int, h http.Header) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return
	}
	if s.requestStarted {
		s.write("\n``````\n")
	}
	s.write(fmt.Sprintf("## Upstream response\n\n`%d`\n\n", status))
	s.headers(h)
}
func (s *Session) Body(p []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return
	}
	if !s.responseStarted {
		s.responseStarted = true
		s.write("## Response body\n\n``````\n")
	}
	s.responseHash.Write(p)
	s.responseBytes += int64(len(p))
	s.bytes(p)
}

// Diagnostic records only the classifier's fixed fields, never the error cause.
func (s *Session) Diagnostic(d observability.Detail) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.completed {
		s.failure = d
	}
}
func (s *Session) Complete(outcome string, status int, code string, duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.completed {
		return
	}
	s.completed = true
	defer s.store.releaseDay(s.record.Started.UTC().Format("2006-01-02"))
	defer func() {
		s.store.mu.Lock()
		delete(s.store.active, s.partial)
		delete(s.store.active, s.complete)
		s.store.mu.Unlock()
	}()
	finalizeStarted := time.Now()
	if s.responseStarted {
		s.write("\n``````\n")
	}
	truncated := s.requestBytes+s.responseBytes > s.captured
	s.write(fmt.Sprintf("## Completion\n\n- Outcome: `%s`\n- Request bytes: `%d`\n- Request SHA-256: `%s`\n- Response bytes: `%d`\n- Response SHA-256: `%s`\n- Capture truncated: `%t`\n- Error code: `%s`\n- Completed UTC: `%s`\n", outcome, s.requestBytes, hex.EncodeToString(s.requestHash.Sum(nil)), s.responseBytes, hex.EncodeToString(s.responseHash.Sum(nil)), truncated, inline(code), time.Now().UTC().Format(time.RFC3339Nano)))
	flushStarted := s.store.performanceStart()
	if e := s.buffer.Flush(); e != nil {
		s.store.captureFailure("capture_flush", e)
		s.failed = true
	}
	s.store.performance("capture_flush", flushStarted)
	syncStarted := s.store.performanceStart()
	if e := s.file.Sync(); e != nil {
		s.store.captureFailure("capture_sync", e)
		s.failed = true
	}
	s.store.performance("capture_sync", syncStarted)
	if e := s.file.Close(); e != nil {
		s.store.captureFailure("capture_close", e)
		s.failed = true
	}
	if !s.failed {
		s.store.mu.Lock()
		e := os.Rename(s.partial, s.complete)
		if e == nil {
			s.store.active[s.complete] = true
		}
		s.store.mu.Unlock()
		if e != nil {
			s.store.captureFailure("capture_publish", e)
			s.failed = true
		}
	}
	if s.failed {
		s.store.degraded.Store(true)
	}
	rec := s.record
	summary := map[string]any{"RequestId": rec.RequestID, "StartedAtUtc": rec.Started, "CompletedAtUtc": time.Now().UTC(), "UserId": rec.UserID, "UserSid": rec.Route.UserSID, "Agent": rec.Agent, "AgentSurface": rec.Surface, "ProviderId": rec.Route.ProviderID, "RouteId": rec.Route.RouteID, "OriginalBaseUrl": RedactURL(rec.Route.OriginalBaseURL), "InboundPathAndQuery": RedactURL(rec.Inbound), "StatusCode": status, "DurationMilliseconds": duration.Milliseconds(), "Outcome": outcome, "ErrorCode": nil, "ErrorSummary": nil, "RequestBytes": s.requestBytes, "ResponseBytes": s.responseBytes, "CaptureTruncated": truncated, "CaptureDegraded": s.failed, "MarkdownPath": s.complete}
	for key, value := range observability.Fields(s.failure) {
		summary[key] = value
	}
	summary["CaptureFinalizeMilliseconds"] = float64(time.Since(finalizeStarted).Microseconds()) / 1000
	if code != "" {
		summary["ErrorCode"] = code
	}
	for key, at := range s.timing {
		summary[key] = at
	}
	u, _ := url.Parse(rec.Outbound)
	if u != nil {
		summary["OutboundPathAndQuery"] = RedactURL(u.RequestURI())
	}
	if start, ok := s.timing["GatewayRequestStartedAtUtc"]; ok {
		if end, ok := s.timing["GatewayResponseHeadersReceivedAtUtc"]; ok {
			summary["GatewayRoundTripMilliseconds"] = end.Sub(start).Milliseconds()
		}
	}
	if e := s.store.append(filepath.Join(s.store.Root, "captures", "summary", rec.Started.Format("2006-01-02")+".jsonl"), summary); e != nil {
		s.store.captureFailure("summary_append", e)
	}
	if !s.failed {
		select {
		case s.store.queue <- s.complete:
		default:
		}
	}
}

func (s *Store) writeLog(value map[string]any) error {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	day := time.Now().UTC().Format("2006-01-02")
	if s.logFile == nil || !strings.HasPrefix(filepath.Base(s.logPath), day) || s.logBytes >= s.LogFileLimit {
		if s.logFile != nil {
			old := s.logPath
			if e := s.logFile.Sync(); e != nil {
				return e
			}
			if e := s.logFile.Close(); e != nil {
				return e
			}
			s.mu.Lock()
			delete(s.active, old)
			s.mu.Unlock()
			s.logFile = nil
			select {
			case s.queue <- old:
			default:
			}
		}
		dir := filepath.Join(s.Root, "logs", "service")
		if e := os.MkdirAll(dir, 0700); e != nil {
			return e
		}
		s.logPath = filepath.Join(dir, day+"-"+strings.ReplaceAll(proxy.UUID(), "-", "")+".jsonl")
		f, e := os.OpenFile(s.logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		s.logFile = f
		s.logBytes = 0
		s.mu.Lock()
		s.active[s.logPath] = true
		s.mu.Unlock()
	}
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	n, e := s.logFile.Write(append(b, '\n'))
	s.logBytes += int64(n)
	return e
}

// FlushLogs drains a bounded snapshot of queued diagnostics. Producers never wait for it.
func (s *Store) FlushLogs() {
	for i := 0; i < cap(s.logQueue)+cap(s.priorityQueue); i++ {
		select {
		case value := <-s.priorityQueue:
			s.persistLog(value)
			continue
		default:
		}
		select {
		case value := <-s.logQueue:
			s.persistLog(value)
		default:
			return
		}
	}
}
func (s *Store) persistLog(value map[string]any) {
	if at, ok := value["TimestampUtc"].(time.Time); ok {
		value["QueueWaitMilliseconds"] = float64(time.Since(at).Microseconds()) / 1000
	}
	if e := s.writeLog(value); e != nil {
		s.writeFailures.Add(1)
	}
}
func (s *Store) CloseLogs() {
	s.closeSummaries()
	s.flushStatistics()
	s.FlushLogs()
	s.logMu.Lock()
	defer s.logMu.Unlock()
	if s.logFile != nil {
		if e := s.logFile.Sync(); e != nil {
			s.writeFailures.Add(1)
		}
		if e := s.logFile.Close(); e != nil {
			s.writeFailures.Add(1)
		}
		s.mu.Lock()
		delete(s.active, s.logPath)
		s.mu.Unlock()
		s.logFile = nil
	}
}

// Run has exactly two workers: diagnostic persistence is independent of gzip/retention.
// The caller cancels this context only after HTTP handlers have drained.
func (s *Store) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.runMaintenance(ctx) }()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case value := <-s.priorityQueue:
			s.persistLog(value)
			continue
		default:
		}
		select {
		case <-ctx.Done():
			wg.Wait()
			s.CloseLogs()
			return
		case value := <-s.priorityQueue:
			s.persistLog(value)
		case value := <-s.logQueue:
			s.persistLog(value)
		case <-tick.C:
			s.flushStatistics()
		}
	}
}
func (s *Store) compress(path string) error {
	started := s.performanceStart()
	defer func() { s.performance("compression", started) }()
	s.compressionMu.Lock()
	defer s.compressionMu.Unlock()
	if s.isSummary(path) {
		s.summaryMu.Lock()
		defer s.summaryMu.Unlock()
		if s.summaryActiveLocked(path, time.Now().UTC()) {
			return nil
		}
		if e := s.closeSummaryLocked(path); e != nil {
			return e
		}
	}
	info, e := os.Lstat(path)
	if e != nil {
		if os.IsNotExist(e) {
			return nil
		}
		return e
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	s.mu.Lock()
	active := s.active[path]
	s.mu.Unlock()
	if active {
		return nil
	}
	if _, e = os.Lstat(path + ".gz"); e == nil {
		return nil
	}
	in, e := os.Open(path)
	if e != nil {
		return e
	}
	defer in.Close()
	// A crash may leave an unpublished gzip temporary. The durable raw input
	// still exists, so retry from it rather than permanently blocking backlog.
	if temporary, err := os.Lstat(path + ".gz.tmp"); err == nil {
		if !temporary.Mode().IsRegular() {
			return fmt.Errorf("compression temporary is not a regular file")
		}
		if err = os.Remove(path + ".gz.tmp"); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	out, e := os.OpenFile(path+".gz.tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	ok := false
	defer func() {
		out.Close()
		if !ok {
			os.Remove(path + ".gz.tmp")
		}
	}()
	// The legacy compressor uses CompressionLevel.Fastest. Request evidence
	// is bounded and retained by size; prefer the same CPU/latency tradeoff.
	z, e := gzip.NewWriterLevel(out, gzip.BestSpeed)
	if e != nil {
		return e
	}
	if _, e = io.Copy(z, in); e != nil {
		z.Close()
		return e
	}
	if e = z.Close(); e != nil {
		return e
	}
	if e = in.Close(); e != nil {
		return e
	}
	if e = out.Sync(); e != nil {
		return e
	}
	if e = out.Close(); e != nil {
		return e
	}
	if e = os.Rename(path+".gz.tmp", path+".gz"); e != nil {
		return e
	}
	_ = os.Chtimes(path+".gz", info.ModTime(), info.ModTime())
	if e = os.Remove(path); e != nil {
		return e
	}
	ok = true
	return nil
}

type managedFile struct {
	path string
	info os.FileInfo
}

func (s *Store) Maintain(now time.Time) {
	for _, scope := range []struct {
		dir             string
		maximum, target int64
	}{{"captures", 512 << 20, 512 << 20}, {filepath.Join("logs", "service"), 50 << 20, 45 << 20}} {
		var files []managedFile
		var total int64
		e := filepath.WalkDir(filepath.Join(s.Root, scope.dir), func(path string, d os.DirEntry, walkErr error) error {
			if os.IsNotExist(walkErr) {
				return nil
			}
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			name := d.Name()
			if !(strings.HasSuffix(name, ".md") || strings.HasSuffix(name, ".md.gz") || strings.HasSuffix(name, ".partial") || strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".jsonl.gz")) {
				return nil
			}
			info, e := d.Info()
			// Capture publication can rename an entry after WalkDir enumerates it.
			if os.IsNotExist(e) {
				return nil
			}
			if e != nil {
				return e
			}
			s.mu.Lock()
			active := s.active[path]
			s.mu.Unlock()
			currentSummary := false
			if s.isSummary(path) {
				s.summaryMu.Lock()
				currentSummary = s.summaryActiveLocked(path, now)
				s.summaryMu.Unlock()
			}
			if active || currentSummary {
				total += info.Size()
				return nil
			}
			files = append(files, managedFile{path, info})
			total += info.Size()
			return nil
		})
		if e != nil {
			s.maintenanceFailure(scope.dir, "retention_scan", e)
			continue
		}
		sort.Slice(files, func(i, j int) bool { return files[i].info.ModTime().Before(files[j].info.ModTime()) })
		for i := range files {
			if now.Sub(files[i].info.ModTime()) > 7*24*time.Hour {
				if removed, e := s.removeManaged(files[i].path, now); removed {
					total -= files[i].info.Size()
					files[i].path = ""
				} else if e != nil {
					s.maintenanceFailure(scope.dir, "retention_delete", e)
				}
			}
		}
		if total > scope.maximum {
			for i := range files {
				if total <= scope.target {
					break
				}
				if files[i].path != "" {
					if removed, e := s.removeManaged(files[i].path, now); removed {
						total -= files[i].info.Size()
						files[i].path = ""
					} else if e != nil {
						s.maintenanceFailure(scope.dir, "retention_delete", e)
					}
				}
			}
		}
		for _, file := range files {
			if file.path != "" && (strings.HasSuffix(file.path, ".md") || strings.HasSuffix(file.path, ".jsonl")) {
				select {
				case s.queue <- file.path:
				default:
				}
			}
		}
	}
}

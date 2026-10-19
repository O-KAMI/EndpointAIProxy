package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"endpointai/client/internal/observability"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Failure contains only typed diagnostics, never paths or arbitrary error messages.
type Failure struct {
	Stage        string    `json:"stage"`
	ErrorClass   string    `json:"errorClass"`
	OSCode       int64     `json:"osCode,omitempty"`
	TimestampUtc time.Time `json:"timestampUtc"`
}
type DiagnosticsSnapshot struct {
	AuditFailureCount    int64   `json:"auditFailureCount"`
	LastAuditFailure     Failure `json:"lastAuditFailure"`
	LogDroppedCount      int64   `json:"logDroppedCount"`
	LogWriteFailureCount int64   `json:"logWriteFailureCount"`
	LogSuppressedCount   int64   `json:"logSuppressedCount"`
	LogQueueDepth        int     `json:"logQueueDepth"`
}

func (s *Store) Snapshot() DiagnosticsSnapshot {
	s.telemetryMu.Lock()
	v := s.telemetry
	s.telemetryMu.Unlock()
	v.LogDroppedCount = s.dropped.Load()
	v.LogWriteFailureCount = s.writeFailures.Load()
	v.LogSuppressedCount = s.suppressed.Load()
	v.LogQueueDepth = len(s.logQueue) + len(s.priorityQueue)
	return v
}
func (s *Store) maintenanceFailure(scope, stage string, err error) {
	if scope == "captures" {
		s.captureFailure(stage, err)
	} else {
		s.writeFailures.Add(1)
	}
}
func (s *Store) captureFailure(stage string, err error) {
	d := observability.Classify(err)
	s.degraded.Store(true)
	s.telemetryMu.Lock()
	s.telemetry.AuditFailureCount++
	s.telemetry.LastAuditFailure = Failure{Stage: stage, ErrorClass: d.Class, OSCode: int64(d.OSCode), TimestampUtc: time.Now().UTC()}
	count := s.telemetry.AuditFailureCount
	s.telemetryMu.Unlock()
	d.Stage = stage
	fields := observability.Fields(d)
	fields["count"] = count
	s.Log("AUDIT_FAILURE", fields)
}

var tokenPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,100}$`)
var prehashedIdentifierPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var identifierPattern = regexp.MustCompile(`^[a-fA-F0-9-]{1,64}$`)

func boundedToken(v any) (any, bool) {
	x, ok := v.(string)
	return x, ok && tokenPattern.MatchString(x)
}

// sanitizeLogFields is intentionally an allowlist, so new callers cannot leak free text.
func sanitizeLogFields(fields map[string]any) map[string]any {
	out := make(map[string]any, 16)
	scanned := 0
	for k, v := range fields {
		scanned++
		if len(out) >= 32 || scanned > 64 {
			break
		}
		switch strings.ToLower(k) {
		case "requestid", "routeid", "commandid", "deviceid", "controlenvelopeid", "controlrequestid", "serverrequestid", "operationid", "runid", "userhash", "pathhash", "providerhash":
			if x, ok := v.(string); ok && len(x) <= 256 {
				if identifierPattern.MatchString(x) || prehashedIdentifierPattern.MatchString(x) {
					out[k] = x
				} else {
					h := sha256.Sum256([]byte(x))
					out[k] = "sha256:" + hex.EncodeToString(h[:])
				}
			}
		case "code", "errorcode", "errorclass", "stage", "component", "operation", "outcome", "implementation", "resultcode", "agent", "agentsurface", "family", "mode", "source", "ownership", "lastcontrolerrorcode":
			if x, ok := boundedToken(v); ok {
				out[k] = x
			}
		case "version":
			if x, ok := v.(string); ok && len(x) <= 32 && regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9]+)*$`).MatchString(x) {
				out[k] = x
			}
		case "status":
			switch v.(type) {
			case int, int64, float64:
				out[k] = v
			case string:
				if x, ok := boundedToken(v); ok {
					out[k] = x
				}
			}
		case "failed", "changed":
			switch v.(type) {
			case bool, int, int64, float64:
				out[k] = v
			}
		case "statuscode", "agenttype", "commandtype", "type", "failurecount", "durationmilliseconds", "capturefinalizemilliseconds", "items", "policyversion", "oscode", "oserrorcode", "httpstatuscode", "count", "droppedcount", "suppressedcount", "requestbytes", "responsebytes", "rollbackcount", "queuewaitmilliseconds":
			switch v.(type) {
			case int, int64, int32, uint, uint64, uint32, float64:
				out[k] = v
			}
		case "enabled", "restored", "concurrentchange", "capturedegraded", "partial", "timeout":
			if x, ok := v.(bool); ok {
				out[k] = x
			}
		case "timestamp", "timestamputc", "firstatutc", "lastatutc", "lastcontrolsyncatutc", "firstfailureatutc", "lastfailureatutc":
			if x, ok := v.(time.Time); ok {
				out[k] = x.UTC()
			}
		}
	}
	return out
}
func (s *Store) Log(code string, fields map[string]any) {
	if !tokenPattern.MatchString(code) {
		code = "INVALID_EVENT_CODE"
	}
	now := time.Now().UTC()
	if code == "REQUEST_COMPLETED" {
		status, _ := fields["status"].(int)
		outcome, _ := fields["outcome"].(string)
		if status < 400 && (strings.EqualFold(outcome, "success") || strings.EqualFold(outcome, "succeeded")) {
			s.statisticsMu.Lock()
			s.statistics["successfulRequests"]++
			for _, spec := range []struct{ key, sum, max string }{{"durationMilliseconds", "durationMillisecondsSum", "durationMillisecondsMax"}, {"captureFinalizeMilliseconds", "captureFinalizeMillisecondsSum", "captureFinalizeMillisecondsMax"}} {
				key := spec.key
				var value float64
				switch v := fields[key].(type) {
				case int64:
					value = float64(v)
				case float64:
					value = v
				case int:
					value = float64(v)
				}
				micros := int64(value * 1000)
				s.statistics[spec.sum] += micros
				if micros > s.statistics[spec.max] {
					s.statistics[spec.max] = micros
				}
			}
			s.statisticsMu.Unlock()
			return
		}
	}
	value := sanitizeLogFields(fields)
	value["TimestampUtc"] = now
	value["Code"] = code
	failed, _ := fields["failed"].(bool)
	priority := failed || strings.HasPrefix(code, "SERVICE_") || strings.Contains(code, "FAIL") || strings.Contains(code, "ERROR") || code == "REQUEST_COMPLETED"
	if priority && !strings.HasPrefix(code, "SERVICE_") {
		key := fmt.Sprint(code, ":", value["stage"], ":", value["errorClass"], ":", value["operation"])
		s.statisticsMu.Lock()
		window, ok := s.rate[key]
		if !ok && len(s.rate) >= 128 {
			s.statistics["suppressedEvents"]++
			s.suppressed.Add(1)
			s.statisticsMu.Unlock()
			return
		}
		if !ok {
			window = rateWindow{first: now, fields: map[string]any{"Code": code, "stage": value["stage"], "errorClass": value["errorClass"], "operation": value["operation"]}}
		}
		window.last = now
		window.count++
		suppress := ok && now.Sub(window.emitted) < 10*time.Second
		if suppress {
			window.suppressed++
			s.statistics["suppressedEvents"]++
			s.suppressed.Add(1)
		} else {
			window.emitted = now
		}
		s.rate[key] = window
		s.statisticsMu.Unlock()
		if suppress {
			return
		}
	}
	q := s.logQueue
	if priority {
		q = s.priorityQueue
	}
	select {
	case q <- value:
	default:
		s.dropped.Add(1)
	}
}
func (s *Store) flushStatistics() {
	s.statisticsMu.Lock()
	stats := s.statistics
	windows := s.rate
	s.statistics = make(map[string]int64)
	s.rate = make(map[string]rateWindow)
	s.statisticsMu.Unlock()
	dropped := s.dropped.Load()
	delta := dropped - s.lastReportedDrops
	s.lastReportedDrops = dropped
	if len(stats) == 0 && delta == 0 {
		return
	}
	value := map[string]any{"TimestampUtc": time.Now().UTC(), "Code": "LOG_MINUTE_SUMMARY", "SuccessfulRequestCount": stats["successfulRequests"], "SuppressedCount": stats["suppressedEvents"], "DroppedCount": delta, "DurationSumMilliseconds": float64(stats["durationMillisecondsSum"]) / 1000, "DurationMaxMilliseconds": float64(stats["durationMillisecondsMax"]) / 1000, "CaptureFinalizeSumMilliseconds": float64(stats["captureFinalizeMillisecondsSum"]) / 1000, "CaptureFinalizeMaxMilliseconds": float64(stats["captureFinalizeMillisecondsMax"]) / 1000}
	s.persistLog(value)
	for _, w := range windows {
		if w.suppressed == 0 {
			continue
		}
		event := map[string]any{"TimestampUtc": time.Now().UTC(), "Code": "LOG_FAILURES_SUPPRESSED", "EventCode": w.fields["Code"], "stage": w.fields["stage"], "errorClass": w.fields["errorClass"], "operation": w.fields["operation"], "Count": w.count, "SuppressedCount": w.suppressed, "FirstAtUtc": w.first, "LastAtUtc": w.last}
		s.persistLog(event)
	}
}

type rateWindow struct {
	first, last, emitted time.Time
	count, suppressed    int64
	fields               map[string]any
}

package diagnostics

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEvidenceTailAndTimestampTopN(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(root, "captures", "summary")
	os.MkdirAll(dir, 0700)
	f, _ := os.Create(filepath.Join(dir, "fixture.jsonl"))
	now := time.Now().UTC()
	old := now.Add(-time.Minute)
	// More than 8 MiB before the newest failure; regular collection must seek tail.
	pad := strings.Repeat("x", 16<<10)
	for i := 0; i < 600; i++ {
		fmt.Fprintf(f, "{\"StartedAtUtc\":%q,\"Padding\":%q,\"StatusCode\":200}\n", old.Format(time.RFC3339Nano), pad)
	}
	for i := 0; i < 250; i++ {
		fmt.Fprintf(f, "{\"StartedAtUtc\":%q,\"StatusCode\":502,\"RequestId\":\"10000000-0000-0000-0000-%012d\"}\n", now.Add(time.Duration(i)*time.Millisecond).Format(time.RFC3339Nano), i)
	}
	id := "10000000-0000-0000-0000-000000000249"
	f.Close()
	summary, failures, _, _, coverage, errs, partial := readEvidenceWindow(context.Background(), Options{DataRoot: root}, old.Add(-time.Second))
	if len(errs) > 0 || !partial || len(summary) != 200 || len(failures) != 200 || summary[0]["RequestId"] != id || failures[0]["RequestId"] != id {
		t.Fatal(len(summary), len(failures), errs, coverage)
	}
	summary, _, _, _, coverage, errs, partial = readEvidenceWindow(context.Background(), Options{DataRoot: root, RequestID: id}, old.Add(-time.Second))
	if len(errs) > 0 || partial || len(summary) != 1 || coverage["requestFound"] != true {
		t.Fatal(summary, coverage, errs, partial)
	}
	original := filepath.Join(dir, "fixture.jsonl")
	input, _ := os.Open(original)
	output, _ := os.Create(original + ".gz")
	gz := gzip.NewWriter(output)
	io.Copy(gz, input)
	gz.Close()
	input.Close()
	output.Close()
	os.Remove(original)
	summary, _, _, _, coverage, errs, partial = readEvidenceWindow(context.Background(), Options{DataRoot: root, RequestID: id}, old.Add(-time.Second))
	if len(errs) > 0 || partial || len(summary) != 1 || coverage["requestFound"] != true {
		t.Fatal("gzip >8MiB", summary, coverage, errs, partial)
	}

}
func TestGzipTimestampOrderingAcrossShardsAndSafeFields(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(root, "logs", "service")
	os.MkdirAll(dir, 0700)
	now := time.Now().UTC()
	for i, name := range []string{"z.jsonl.gz", "a.jsonl.gz"} {
		f, _ := os.Create(filepath.Join(dir, name))
		gz := gzip.NewWriter(f)
		json.NewEncoder(gz).Encode(map[string]any{"TimestampUtc": now.Add(time.Duration(i) * time.Second), "Code": "CONTROL_FAILED", "errorClass": "TLS_EXPIRED", "controlRequestId": "10000000-0000-0000-0000-000000000001", "DroppedCount": 7, "failed": true, "Secret": "api-secret"})
		gz.Close()
		f.Close()
	}
	_, _, logs, _, coverage, errs, partial := readEvidenceWindow(context.Background(), Options{DataRoot: root}, now.Add(-time.Hour))
	if partial || len(errs) > 0 || len(logs) != 2 || logs[0]["TimestampUtc"] != now.Add(time.Second).Format(time.RFC3339Nano) {
		t.Fatal(logs, coverage, errs)
	}
	b, _ := json.Marshal(logs)
	if strings.Contains(string(b), "api-secret") || logs[0]["DroppedCount"] != float64(7) || logs[0]["failed"] != true {
		t.Fatal(string(b))
	}
	health := sanitizeRow(map[string]any{"auditDiagnostics": map[string]any{"logDroppedCount": float64(9), "lastAuditFailure": map[string]any{"stage": "capture_sync", "errorClass": "DISK_FULL", "osCode": float64(28), "secret": "api-secret"}}, "lastControlErrorCode": "POLICY_SIGNATURE_INVALID", "lastControlSyncAtUtc": now.Format(time.RFC3339Nano), "policyVersion": float64(4)})
	b, _ = json.Marshal(health)
	if strings.Contains(string(b), "api-secret") || health["policyVersion"] != float64(4) || health["lastControlErrorCode"] == nil {
		t.Fatal(string(b))
	}
}

func TestPrehashedOperationalIdentifierMatchesSummary(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	route := "legacy-route-fixture"
	hashed := hashIdentifier(route)
	for _, fixture := range []struct {
		dir string
		row map[string]any
	}{{"captures/summary", map[string]any{"StartedAtUtc": now, "RouteId": route, "StatusCode": 502}}, {"logs/service", map[string]any{"TimestampUtc": now, "routeId": hashed, "userHash": hashed, "pathHash": hashed, "providerHash": hashed, "Code": "REQUEST_COMPLETED"}}} {
		dir := filepath.Join(root, filepath.FromSlash(fixture.dir))
		os.MkdirAll(dir, 0700)
		b, _ := json.Marshal(fixture.row)
		os.WriteFile(filepath.Join(dir, "fixture.jsonl"), append(b, '\n'), 0600)
	}
	summary, _, logs, _, _, errs, _ := readEvidenceWindow(context.Background(), Options{DataRoot: root}, now.Add(-time.Hour))
	if len(errs) > 0 || len(summary) != 1 || len(logs) != 1 || summary[0]["RouteId"] != hashed || logs[0]["routeId"] != hashed || logs[0]["userHash"] != hashed || logs[0]["pathHash"] != hashed || logs[0]["providerHash"] != hashed {
		t.Fatal(summary, logs, errs)
	}
	for _, raw := range []string{"sha256:credential", strings.ToUpper(hashed), hashed + "token"} {
		if sanitizeRow(map[string]any{"RouteId": raw})["RouteId"] == raw {
			t.Fatal("invalid hash trusted", raw)
		}
	}
}

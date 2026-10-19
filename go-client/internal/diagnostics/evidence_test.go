package diagnostics

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBoundedGzipEvidenceAndBodyRemoval(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := "10000000-0000-0000-0000-000000000001"
	capture := filepath.Join(root, "captures", "fixture.md.gz")
	if e := os.MkdirAll(filepath.Join(root, "captures", "summary"), 0700); e != nil {
		t.Fatal(e)
	}
	f, e := os.Create(capture)
	if e != nil {
		t.Fatal(e)
	}
	gz := gzip.NewWriter(f)
	gz.Write([]byte("# Capture\n- Request ID: `" + id + "`\n- User ID: `private-user`\n## Request body\nBODY_SECRET\n## Completion\n- Request bytes: `12`\n- Error summary: `API_SECRET`\n- Outcome: `Failed`\n"))
	gz.Close()
	f.Close()
	row := map[string]any{"RequestId": id, "StartedAtUtc": time.Now().UTC().Format(time.RFC3339Nano), "StatusCode": 500, "MarkdownPath": capture, "ErrorSummary": "API_SECRET", "UserId": "private-user", "Authorization": "AUTH_SECRET", "RequestBytes": 12}
	b, _ := json.Marshal(row)
	os.WriteFile(filepath.Join(root, "captures", "summary", "fixture.jsonl"), append(b, '\n'), 0600)
	logRoot := filepath.Join(root, "logs", "service")
	os.MkdirAll(logRoot, 0700)
	f, _ = os.Create(filepath.Join(logRoot, "fixture.jsonl.gz"))
	gz = gzip.NewWriter(f)
	logRow := map[string]any{"TimestampUtc": time.Now().UTC().Format(time.RFC3339Nano), "Level": 3, "EventName": "CCSWITCH_PROXY_STATE_INCONSISTENT", "RequestId": id, "Message": "API_SECRET"}
	logBytes, _ := json.Marshal(logRow)
	gz.Write(append(logBytes, '\n'))
	gz.Close()
	f.Close()
	out, errs, _ := collectEvidence(context.Background(), Options{DataRoot: root, RequestID: id}, time.Now().Add(-time.Hour))
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	for name, data := range out {
		for _, secret := range []string{"BODY_SECRET", "API_SECRET", "private-user", "AUTH_SECRET"} {
			if strings.Contains(string(data), secret) {
				t.Fatalf("%s leaked %s", name, secret)
			}
		}
	}
	md := string(out["requests/sanitized-captures/"+strings.ReplaceAll(id, "-", "")+".md"])
	if !strings.Contains(md, "[OMITTED]") || !strings.Contains(md, "Request bytes") {
		t.Fatal(md)
	}
	if len(out["service/operational-log.jsonl"]) == 0 || len(out["requests/failures.jsonl"]) == 0 {
		t.Fatal("missing failure evidence")
	}
}
func TestDiagnosticOptionsRejectInvalidRangeAndID(t *testing.T) {
	for _, o := range []Options{{Since: time.Minute}, {Since: 169 * time.Hour}, {RequestID: "not-a-guid"}} {
		if _, e := Collect(context.Background(), o); e == nil {
			t.Fatal("invalid options accepted")
		}
	}
}

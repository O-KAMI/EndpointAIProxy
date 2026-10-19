package diagnostics

import (
	"archive/zip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestHealthAllowlistAndFailureIsolation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"status":"ok","token":"secret","configuration":{"apiKey":"secret"}}`)
	}))
	defer srv.Close()
	r := collectHealth(context.Background(), srv.URL).(map[string]any)
	if r["status"] != "ok" || r["token"] != nil || r["configuration"] != nil {
		t.Fatal(r)
	}
	path, e := Collect(context.Background(), Options{DataRoot: t.TempDir(), OutputPath: filepath.Join(t.TempDir(), "fixture.zip"), HealthURL: "http://127.0.0.1:1/healthz"})
	if e != nil {
		t.Fatal(e)
	}
	z, e := zip.OpenReader(path)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	found := false
	for _, f := range z.File {
		if f.Name == "health.json" {
			reader, _ := f.Open()
			var failure result
			e = json.NewDecoder(reader).Decode(&failure)
			reader.Close()
			if e != nil || failure.Error != "health_unavailable" {
				t.Fatal(failure, e)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("health evidence missing")
	}
}

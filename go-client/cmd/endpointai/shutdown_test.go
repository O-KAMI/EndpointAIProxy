package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestShutdownDrainsRequestBeforeClosingOperationalLog(t *testing.T) {
	opts := isolatedOptions(t)
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	opts.app.Listen = probe.Addr().String()
	probe.Close()
	finish := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-finish:
		case <-r.Context().Done():
			return
		}
		io.WriteString(w, "data: done\n\n")
	}))
	defer upstream.Close()
	t.Setenv("SF_PROXY_BOOTSTRAP_UPSTREAM", upstream.URL)
	t.Setenv("SF_PROXY_BOOTSTRAP_ROUTE_ID", "abcdefghijklmnopqrstuv")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, opts) }()
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, e := client.Get("http://" + opts.app.Listen + "/healthz")
		if e == nil {
			response.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			close(finish)
			t.Fatal("health never ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	response, err := client.Get("http://" + opts.app.Listen + "/r/abcdefghijklmnopqrstuv/stream")
	if err != nil {
		close(finish)
		t.Fatal(err)
	}
	reader := bufio.NewReader(response.Body)
	if _, err = reader.ReadString('\n'); err != nil {
		close(finish)
		t.Fatal(err)
	}
	cancel()
	select {
	case <-done:
		close(finish)
		t.Fatal("service stopped before in-flight request completed")
	case <-time.After(50 * time.Millisecond):
	}
	close(finish)
	_, err = io.Copy(io.Discard, reader)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("shutdown did not drain")
	}
	files, _ := filepath.Glob(filepath.Join(opts.app.DataRoot, "logs/service/*.jsonl"))
	var successes float64
	stopped := false
	for _, path := range files {
		f, e := os.Open(path)
		if e != nil {
			t.Fatal(e)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var row map[string]any
			if e = json.Unmarshal(scanner.Bytes(), &row); e != nil {
				t.Fatal(e)
			}
			if row["Code"] == "LOG_MINUTE_SUMMARY" {
				if n, ok := row["SuccessfulRequestCount"].(float64); ok {
					successes += n
				}
			}
			if row["Code"] == "SERVICE_STOPPED" {
				stopped = true
			}
		}
		f.Close()
	}
	if successes != 1 || !stopped {
		t.Fatalf("last request/stop log lost: successes=%v stopped=%v", successes, stopped)
	}
}

func TestStartupFailureRetainsSafeCode(t *testing.T) {
	opts := isolatedOptions(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	opts.app.Listen = listener.Addr().String()
	fields := startupFailure(run(context.Background(), opts))
	if fields["errorCode"] != "CLIENT_ENDPOINT_IN_USE" || fields["stage"] != "listener" {
		t.Fatal(fields)
	}
}

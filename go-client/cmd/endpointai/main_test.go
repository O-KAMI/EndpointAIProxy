package main

import (
	"bytes"
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

func isolatedOptions(t *testing.T) options {
	t.Helper()
	root := t.TempDir()
	profile := filepath.Join(root, "profile")
	if e := os.Mkdir(profile, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(profile, ".endpointai-e2e-profile"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("SF_PROXY_DATA_ROOT", filepath.Join(root, "data"))
	t.Setenv("SF_PROXY_CONTROL_ORIGIN", "")
	t.Setenv("SF_PROXY_E2E_PROFILE_ROOT", profile)
	t.Setenv("SF_PROXY_AUTO_ATTACH", "false")
	t.Setenv("DOTNET_ENVIRONMENT", "Development")
	t.Setenv("SF_PROXY_ROUTE_MODE", "PassthroughOriginal")
	t.Setenv("SF_PROXY_GATEWAY_HMAC_KEY", "")
	t.Setenv("SF_PROXY_ENABLE_MANAGEMENT_API", "false")
	opts, e := parse(nil)
	if e != nil {
		t.Fatal(e)
	}
	return opts
}

func TestOptionIsolationAndInvalidInputs(t *testing.T) {
	opts := isolatedOptions(t)
	if opts.app.Control != nil || opts.app.AutoAttach || !opts.development {
		t.Fatal("isolation flags lost")
	}
	for _, args := range [][]string{{"--unknown=true"}, {"--maintenance=erase"}, {"--auto-attach=maybe"}, {"--diagnostics-since-hours=0"}, {"--diagnostics-since-hours=169"}, {"--route-mode=invalid"}} {
		if _, e := parse(args); e == nil {
			t.Fatalf("invalid option accepted: %v", args)
		}
	}
	t.Setenv("DOTNET_ENVIRONMENT", "Production")
	if _, e := parse(nil); e == nil {
		t.Fatal("unmarked production profile override accepted")
	}
}

func TestLegacyListenerBlocksStateMutation(t *testing.T) {
	opts := isolatedOptions(t)
	listener, e := net.Listen("tcp4", opts.app.Listen)
	if e != nil {
		t.Skip("port 18080 already in use; no running service was touched")
	}
	defer listener.Close()
	if e = run(context.Background(), opts); e == nil {
		t.Fatal("existing listener ignored")
	}
	if _, e = os.Stat(opts.app.DataRoot); !os.IsNotExist(e) {
		t.Fatal("state created before listener ownership was established")
	}
}

func TestIsolatedServiceRestartAndStreaming(t *testing.T) {
	opts := isolatedOptions(t)
	probe, e := net.Listen("tcp4", opts.app.Listen)
	if e != nil {
		t.Skip("port 18080 already in use; no running service was touched")
	}
	probe.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(30 * time.Millisecond)
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()
	t.Setenv("SF_PROXY_BOOTSTRAP_UPSTREAM", upstream.URL+"/v1")
	t.Setenv("SF_PROXY_BOOTSTRAP_ROUTE_ID", "abcdefghijklmnopqrstuv")
	var identity string
	for restart := 0; restart < 2; restart++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- run(ctx, opts) }()
		t.Cleanup(cancel)
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
		var healthy map[string]any
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			response, e := client.Get("http://" + opts.app.Listen + "/healthz")
			if e == nil {
				e = json.NewDecoder(response.Body).Decode(&healthy)
				response.Body.Close()
				if e == nil && healthy["status"] == "ok" {
					break
				}
			}
			select {
			case e := <-done:
				t.Fatalf("service exited before health: %v", e)
			default:
			}
			time.Sleep(10 * time.Millisecond)
		}
		if healthy["status"] != "ok" || healthy["implementation"] != "go" {
			t.Fatal("service not ready")
		}
		id, _ := healthy["deviceId"].(string)
		if restart == 0 {
			identity = id
		} else if identity != id {
			t.Fatal("device identity changed across restart")
		}
		request, _ := http.NewRequest("POST", "http://"+opts.app.Listen+"/r/abcdefghijklmnopqrstuv/stream", bytes.NewBufferString(`{"synthetic":true}`))
		request.Header.Set("Content-Type", "application/json")
		response, e := client.Do(request)
		if e != nil {
			t.Fatal(e)
		}
		b, e := io.ReadAll(response.Body)
		response.Body.Close()
		if e != nil || !bytes.Contains(b, []byte("[DONE]")) {
			t.Fatal("stream lost", e)
		}
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Fatal(e)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("service shutdown timed out")
		}
		client.CloseIdleConnections()
	}
}

func TestDSHDeploymentOptions(t *testing.T) {
	isolatedOptions(t)
	t.Setenv("SF_PROXY_ENABLE_DSH", "false")
	t.Setenv("SF_PROXY_DSH_HOMES", "")
	defaults, err := parse(nil)
	if err != nil || defaults.app.EnableDSH {
		t.Fatal("DSH must be opt-in", err)
	}
	root := t.TempDir()
	encoded, _ := json.Marshal([]string{root})
	t.Setenv("SF_PROXY_DSH_HOMES", string(encoded))
	enabled, err := parse([]string{"--enable-dsh=true"})
	if err != nil || !enabled.app.EnableDSH || len(enabled.app.DSHHomes) != 1 || enabled.app.DSHHomes[0] != root {
		t.Fatal("DSH deployment options lost", err)
	}
	for _, args := range [][]string{{"--enable-dsh=maybe"}, {"--dsh-homes=secret-not-json"}, {"--dsh-homes=[\"relative\"]"}} {
		if _, err := parse(args); err == nil {
			t.Fatal("invalid DSH option accepted")
		}
	}
}

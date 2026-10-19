package bench_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"endpointai/client/internal/audit"
	"endpointai/client/internal/contracts"
	"endpointai/client/internal/protect"
	"endpointai/client/internal/proxy"
	"endpointai/client/internal/state"
)

type memoryRoutes struct{ route contracts.Route }

func (s memoryRoutes) FindRoute(context.Context, string) (*contracts.Route, error) {
	r := s.route
	return &r, nil
}

type measurement struct {
	Case                      string `json:"case"`
	FirstByteP95, CompleteP95 float64
}

func TestCapturePerformanceIsolation(t *testing.T) {
	if os.Getenv("ENDPOINTAI_PERF_REPORT") == "" {
		t.Skip("explicit isolated performance investigation")
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(20 * time.Millisecond)
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()
	route := contracts.Route{RouteID: "abcdefghijklmnopqrstuv", UserSID: "synthetic", AgentType: 0, ProviderID: "direct", OriginalBaseURL: upstream.URL, InjectedBaseURL: "http://127.0.0.1:18080/r/abcdefghijklmnopqrstuv", Status: 3, CreatedAtUTC: time.Now().UTC(), UpdatedAtUTC: time.Now().UTC()}
	var measurements []measurement
	for _, kind := range []string{"memory-no-capture", "sqlite-no-capture", "sqlite-capture", "sqlite-capture-gzip"} {
		root := t.TempDir()
		var routes proxy.RouteStore = memoryRoutes{route}
		var db *state.Store
		if kind != "memory-no-capture" {
			key, e := protect.NewFileKey(filepath.Join(root, "machine.key"))
			if e != nil {
				t.Fatal(e)
			}
			db, e = state.Open(filepath.Join(root, "state.db"), key)
			if e != nil {
				t.Fatal(e)
			}
			if e = db.UpsertRoute(context.Background(), route); e != nil {
				t.Fatal(e)
			}
			routes = db
		}
		h := &proxy.Handler{Store: routes, Policy: func() contracts.Policy { return contracts.Policy{Enabled: true, RouteMode: "passthroughOriginal"} }, Transport: proxy.ForwardTransport()}
		logs := audit.New(root)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		if kind == "sqlite-capture-gzip" {
			go func() { logs.Run(ctx); close(done) }()
		} else {
			close(done)
		}
		if kind == "sqlite-capture" || kind == "sqlite-capture-gzip" {
			h.StartCapture = logs.Start
		}
		server := httptest.NewServer(h)
		client := server.Client()
		client.Transport = &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 64}
		var first, complete []float64
		var mu sync.Mutex
		var wg sync.WaitGroup
		slots := make(chan struct{}, 32)
		for i := 0; i < 128; i++ {
			wg.Add(1)
			slots <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-slots }()
				started := time.Now()
				res, e := client.Get(server.URL + "/r/abcdefghijklmnopqrstuv/stream")
				if e != nil {
					t.Error(e)
					return
				}
				var b [1]byte
				_, e = res.Body.Read(b[:])
				fb := float64(time.Since(started).Microseconds()) / 1000
				_, copyErr := io.Copy(io.Discard, res.Body)
				res.Body.Close()
				elapsed := float64(time.Since(started).Microseconds()) / 1000
				if e != nil || copyErr != nil {
					t.Error(e, copyErr)
				}
				mu.Lock()
				first = append(first, fb)
				complete = append(complete, elapsed)
				mu.Unlock()
			}()
		}
		wg.Wait()
		client.CloseIdleConnections()
		server.Close()
		cancel()
		<-done
		if db != nil {
			db.Close()
		}
		sort.Float64s(first)
		sort.Float64s(complete)
		m := measurement{Case: kind, FirstByteP95: first[len(first)*95/100], CompleteP95: complete[len(complete)*95/100]}
		measurements = append(measurements, m)
		t.Logf("%s first p95=%.2fms complete p95=%.2fms", kind, m.FirstByteP95, m.CompleteP95)
	}
	b, e := json.MarshalIndent(measurements, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	path := os.Getenv("ENDPOINTAI_PERF_REPORT")
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, append(b, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	fmt.Println("isolated performance report written")
}

// perf-lab is an isolated synthetic test helper, never an installation payload.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	mode := flag.String("mode", "load", "serve or load")
	origin := flag.String("url", "", "loopback target only")
	count := flag.Int("requests", 1000, "completed measured requests")
	workers := flag.Int("concurrency", 1, "parallel workers")
	warmup := flag.Int("warmup", 100, "unmeasured requests")
	duration := flag.Duration("duration", 0, "minimum measured duration")
	scenario := flag.String("scenario", "json", "json/sse/large")
	cold := flag.Bool("cold", false, "disable connection reuse")
	rps := flag.Float64("rps", 0, "optional total request pacing")
	flag.Parse()
	if *mode == "serve" {
		serve()
		return
	}
	if *mode != "load" || *count < 1 || *workers < 1 || *workers > 128 || *warmup < 0 || !strings.HasPrefix(*origin, "http://127.0.0.1:") {
		fmt.Fprintln(os.Stderr, "invalid isolated load options")
		os.Exit(2)
	}
	path := "/chat/completions"
	switch *scenario {
	case "json":
	case "sse":
		path = "/stream"
	case "large":
		path = "/large"
	default:
		os.Exit(2)
	}
	tr := &http.Transport{Proxy: nil, MaxIdleConns: 256, MaxIdleConnsPerHost: 128, MaxConnsPerHost: 128, DisableKeepAlives: *cold, IdleConnTimeout: 30 * time.Second}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	type sample struct {
		first, last float64
		bytes       int64
		reused      bool
		failed      bool
		detail      string
	}
	request := func() sample {
		began := time.Now()
		body := strings.NewReader(`{"model":"synthetic","messages":[{"role":"user","content":"fixture"}]}`)
		req, e := http.NewRequest("POST", strings.TrimRight(*origin, "/")+path, body)
		if e != nil {
			return sample{failed: true, detail: e.Error()}
		}
		req.Header.Set("Content-Type", "application/json")
		reused := false
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(c httptrace.GotConnInfo) { reused = c.Reused }}))
		resp, e := client.Do(req)
		if e != nil {
			return sample{failed: true, detail: e.Error()}
		}
		var first [1]byte
		n, e := resp.Body.Read(first[:])
		firstElapsed := time.Since(began)
		remaining, readErr := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		detail := ""
		if resp.StatusCode != 200 {
			detail = "http_status=" + strconv.Itoa(resp.StatusCode)
		}
		if e != nil && e != io.EOF {
			detail += " first_read=" + e.Error()
		}
		if readErr != nil {
			detail += " body_read=" + readErr.Error()
		}
		if n != 1 {
			detail += " first_bytes=" + strconv.Itoa(n)
		}
		return sample{detail: detail, first: float64(firstElapsed) / float64(time.Millisecond), last: float64(time.Since(began)) / float64(time.Millisecond), bytes: int64(n) + remaining, reused: reused, failed: resp.StatusCode != 200 || n != 1 || (e != nil && e != io.EOF) || readErr != nil}
	}
	var warmIssued atomic.Int64
	var warmFailed atomic.Bool
	var warm sync.WaitGroup
	for worker := 0; worker < *workers; worker++ {
		warm.Add(1)
		go func() {
			defer warm.Done()
			for warmIssued.Add(1) <= int64(*warmup) {
				r := request()
				if r.failed && warmFailed.CompareAndSwap(false, true) {
					fmt.Fprintln(os.Stderr, "synthetic warmup detail:", r.detail)
				}
			}
		}()
	}
	warm.Wait()
	if warmFailed.Load() {
		fmt.Fprintln(os.Stderr, "synthetic warmup failed")
		os.Exit(1)
	}
	var mu sync.Mutex
	rows := make([]sample, 0, *count)
	var issued atomic.Int64
	began := time.Now()
	deadline := began.Add(*duration)
	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				index := issued.Add(1)
				if index > int64(*count) && !time.Now().Before(deadline) {
					return
				}
				if *rps > 0 {
					wait := time.Until(began.Add(time.Duration(float64(index-1) / *rps * float64(time.Second))))
					if wait > 0 {
						time.Sleep(wait)
					}
				}
				r := request()
				mu.Lock()
				rows = append(rows, r)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	first, last := make([]float64, len(rows)), make([]float64, len(rows))
	failures, reused := 0, 0
	var total int64
	for i, r := range rows {
		first[i], last[i] = r.first, r.last
		total += r.bytes
		if r.failed {
			if failures == 0 {
				fmt.Fprintln(os.Stderr, "synthetic measured detail:", r.detail)
			}
			failures++
		}
		if r.reused {
			reused++
		}
	}
	sort.Float64s(first)
	sort.Float64s(last)
	p95 := func(xs []float64) float64 { return xs[min(len(xs)-1, int(float64(len(xs))*.95))] }
	result := map[string]any{"scenario": *scenario, "concurrency": *workers, "requests": len(rows), "warmup_requests": *warmup, "duration_seconds": time.Since(began).Seconds(), "failures": failures, "reused_connections": reused, "cold_connections": *cold, "bytes": total, "p95_first_byte_ms": p95(first), "p95_last_byte_ms": p95(last), "metric": "agent observed bytes, capture completion verified separately"}
	json.NewEncoder(os.Stdout).Encode(result)
	if failures > 0 {
		os.Exit(1)
	}
}
func serve() {
	mux := http.NewServeMux()
	large := append([]byte(`{"synthetic":"`), bytes.Repeat([]byte("x"), 64<<10)...)
	large = append(large, []byte(`"}`)...)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if strings.HasSuffix(r.URL.Path, "/stream") {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			for _, part := range []string{"data: {\"text\":\"synthetic\"}\n\n", "data: [DONE]\n\n"} {
				io.WriteString(w, part)
				w.(http.Flusher).Flush()
				time.Sleep(20 * time.Millisecond)
			}
			return
		}
		data := []byte(`{"synthetic":true}`)
		if strings.HasSuffix(r.URL.Path, "/large") {
			data = large
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Write(data)
	})
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]string{"origin": "http://" + listener.Addr().String() + "/v1"})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	if server.Serve(listener) != nil {
		os.Exit(1)
	}
}

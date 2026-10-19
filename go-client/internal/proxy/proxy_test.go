package proxy

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"endpointai/client/internal/contracts"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const fixtureID = "abcdefghijklmnopqrstuv"

type fixtureStore struct{ route contracts.Route }

func (s fixtureStore) FindRoute(context.Context, string) (*contracts.Route, error) {
	r := s.route
	return &r, nil
}
func fixtureHandler(upstream string) *Handler {
	return &Handler{Store: fixtureStore{contracts.Route{RouteID: fixtureID, UserSID: "macos:fixture", AgentType: 1, ProviderID: "direct", OriginalBaseURL: upstream}}, Policy: func() contracts.Policy { return contracts.Policy{Enabled: true, RouteMode: "passthroughOriginal"} }, Transport: ForwardTransport()}
}
func TestOriginalForwardPreservesBodyAuthAndStripsSpoof(t *testing.T) {
	body := "{\"stream\":true,\"message\":\"测试\\n\"}"
	observed := make(chan *http.Request, 1)
	payload := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		payload <- string(b)
		observed <- r.Clone(r.Context())
		w.Header().Set("X-Fixture", "response")
		_, _ = io.WriteString(w, "reply")
	}))
	defer upstream.Close()
	proxy := httptest.NewServer(fixtureHandler(upstream.URL + "/v1"))
	defer proxy.Close()
	req, _ := http.NewRequest("POST", proxy.URL+"/r/"+fixtureID+"/responses?x=a%2Fb", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer fixture")
	req.Header.Set("X-Api-Key", "fixture-key")
	req.Header.Set("X-SF-AI-Device-Id", "spoof")
	req.Header.Set("X-SF-AI-Signature", "spoof")
	req.Header.Set("X-Request-Id", "agent-trace")
	req.Header.Set("X-Sf-Userid", "agent-user")
	req.Header.Set("Connection", "X-Hop")
	req.Header.Set("X-Hop", "removed")
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	got := <-observed
	if got.Header.Get("X-Request-ID") != "agent-trace" || got.Header.Get("X-Sf-Userid") != "agent-user" {
		t.Fatal("original-mode ordinary headers changed")
	}
	if string(b) != "reply" || <-payload != body || got.Header.Get("Authorization") != "Bearer fixture" || got.Header.Get("X-Api-Key") != "fixture-key" || got.Header.Get("X-SF-AI-Device-Id") != "" || got.Header.Get("X-SF-AI-Signature") != "" || got.Header.Get("X-Hop") != "" || got.URL.RequestURI() != "/v1/responses?x=a%2Fb" {
		t.Fatal("forwarding contract violated")
	}
}
func TestSSEFirstChunkArrivesBeforeUpstreamCompletes(t *testing.T) {
	finish := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-finish:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "data: last\n\n")
	}))
	defer upstream.Close()
	server := httptest.NewServer(fixtureHandler(upstream.URL))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/r/"+fixtureID+"/stream", nil)
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		close(finish)
		t.Fatal(e)
	}
	defer resp.Body.Close()
	line, e := bufio.NewReader(resp.Body).ReadString('\n')
	close(finish)
	if e != nil || line != "data: first\n" {
		t.Fatal("first SSE event buffered", line, e)
	}
}
func TestFixedGatewayPreservesEscapedPathQueryAndSignsMetadata(t *testing.T) {
	observed := make(chan *http.Request, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { observed <- r.Clone(r.Context()); w.WriteHeader(204) }))
	defer upstream.Close()
	h := fixtureHandler("https://origin.example/base%2Fsegment")
	key := []byte(strings.Repeat("k", 32))
	h.GatewayKey = key
	h.DeviceID = func() string { return "fixture-device" }
	h.Policy = func() contracts.Policy {
		origin := upstream.URL
		return contracts.Policy{Enabled: true, RouteMode: "fixedGateway", GatewayOrigin: &origin, AllowInsecureGateway: true}
	}
	server := httptest.NewServer(h)
	defer server.Close()
	req, _ := http.NewRequest("POST", server.URL+"/r/"+fixtureID+"/responses%2Fencoded?x=%2F&x=2", strings.NewReader("fixture"))
	req.Header.Set("X-SF-AI-Device-Id", "spoof")
	req.Header.Add("x-sf-userid", "spoof-first")
	req.Header.Add("X-SF-USERID", "spoof-second")
	req.Header.Add("x-request-id", "spoof-trace")
	req.Header.Add("X-REQUEST-ID", "spoof-trace-second")
	req.Header.Set("X-SF-AI-Request-Id", "spoof-legacy")
	req.Header.Set("X-SF-AI-User-Id", "spoof-legacy-user")
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	got := <-observed
	if got.URL.RequestURI() != "/base%2Fsegment/responses%2Fencoded?x=%2F&x=2" || got.Header.Get("X-SF-AI-Device-Id") != "fixture-device" {
		t.Fatal(got.URL, got.Header)
	}
	id := got.Header.Get("X-Request-ID")
	if len(id) != 36 || strings.HasPrefix(id, "spoof") || len(got.Header.Values("X-Request-ID")) != 1 || got.Header.Get("X-Sf-Userid") != "fixture" || len(got.Header.Values("X-Sf-Userid")) != 1 || got.Header.Get("X-SF-AI-Request-Id") != "" || got.Header.Get("X-SF-AI-User-Id") != "" {
		t.Fatal("renamed metadata is not authoritative", got.Header)
	}
	values := []string{"v1", id, got.Header.Get("X-SF-AI-Timestamp"), "fixture-device", "fixture", "macos:fixture", "Codex", "unknown", "direct", "https://origin.example/base%2Fsegment", "origin.example", "POST", got.URL.RequestURI()}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(strings.Join(values, "\n")))
	want := "v1:" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if got.Header.Get("X-SF-AI-Signature") != want {
		t.Fatal("gateway signature mismatch")
	}
}
func TestRedirectBlockedAndDisabledPrecedesAllowlist(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://should-not-follow.example")
		w.WriteHeader(307)
	}))
	defer upstream.Close()
	h := fixtureHandler(upstream.URL)
	r := httptest.NewRequest("GET", "http://localhost/r/"+fixtureID+"/responses", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 502 || !strings.Contains(w.Body.String(), "UPSTREAM_REDIRECT_BLOCKED") {
		t.Fatal(w.Code, w.Body.String())
	}
	h.Bypass = func(string) bool { return true }
	h.Enabled = func() bool { return false }
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 500 || !strings.Contains(w.Body.String(), "PROXY_INTERNAL_ERROR") {
		t.Fatal(w.Code, w.Body.String())
	}
	h.Enabled = func() bool { return true }
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestDisconnectCancelsUpstream(t *testing.T) {
	cancelled := make(chan struct{})
	outcomes := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(cancelled)
	}))
	defer upstream.Close()
	h := fixtureHandler(upstream.URL)
	h.Observe = func(_ Record, _ int, outcome string, _ time.Duration) { outcomes <- outcome }
	server := httptest.NewServer(h)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/r/"+fixtureID+"/stream", nil)
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = bufio.NewReader(resp.Body).ReadString('\n')
	resp.Body.Close()
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("disconnect left upstream running")
	}
	select {
	case outcome := <-outcomes:
		if outcome != "CLIENT_CANCELLED" {
			t.Fatalf("disconnect misclassified: %s", outcome)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("disconnect never completed audit observation")
	}
}

// Exercise request-body completion while a persistent upstream starts streaming.
func TestSSEConcurrentRequestBodyCompletion(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
			return
		}
		r.Body.Close()
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(time.Millisecond)
		io.WriteString(w, "data: last\n\n")
		w.(http.Flusher).Flush()
	}))
	defer upstream.Close()
	server := httptest.NewServer(fixtureHandler(upstream.URL))
	defer server.Close()
	client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 8}, Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				resp, err := client.Post(server.URL+"/r/"+fixtureID+"/stream", "application/json", strings.NewReader(`{"fixture":true}`))
				if err != nil {
					t.Error(err)
					return
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || string(body) != "data: first\n\ndata: last\n\n" {
					t.Errorf("truncated stream: %q %v", body, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

type completionReadBody struct {
	io.ReadCloser
	remaining  int64
	flushed    <-chan struct{}
	completion chan<- error
}

func (b *completionReadBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		select {
		case <-b.flushed:
		case <-time.After(3 * time.Second):
			return 0, context.DeadlineExceeded
		}
		n, err := b.ReadCloser.Read(p)
		select {
		case b.completion <- err:
		default:
		}
		return n, err
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, err
}

type completionFlushWriter struct {
	http.ResponseWriter
	flushed chan struct{}
	once    sync.Once
}

func (w *completionFlushWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *completionFlushWriter) Flush() {
	w.ResponseWriter.(http.Flusher).Flush()
	w.once.Do(func() { close(w.flushed) })
}

func TestSSEFlushDoesNotClosePendingForwardedRequestBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(5 * time.Millisecond)
		io.WriteString(w, "data: last\n\n")
	}))
	defer upstream.Close()
	completion := make(chan error, 1)
	handler := fixtureHandler(upstream.URL)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flushed := make(chan struct{})
		r.Body = &completionReadBody{ReadCloser: r.Body, remaining: r.ContentLength, flushed: flushed, completion: completion}
		handler.ServeHTTP(&completionFlushWriter{ResponseWriter: w, flushed: flushed}, r)
	}))
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(server.URL+"/r/"+fixtureID+"/stream", "application/json", strings.NewReader(`{"fixture":true}`))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "data: first\n\ndata: last\n\n" {
		t.Fatalf("truncated SSE: %q %v", body, err)
	}
	select {
	case err := <-completion:
		if err != io.EOF {
			t.Fatalf("request completion read: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("request completion not observed")
	}
}

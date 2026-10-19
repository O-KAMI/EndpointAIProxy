// Package proxy implements the existing loopback route protocol without buffering model responses.
package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"endpointai/client/internal/contracts"
	"endpointai/client/internal/observability"
	"endpointai/client/internal/protocol"
)

type RouteStore interface {
	FindRoute(context.Context, string) (*contracts.Route, error)
}

type Record struct {
	RequestID                                 string
	Route                                     contracts.Route
	Started                                   time.Time
	UserID, Agent, Surface, Inbound, Outbound string
	GatewayRoundTripMilliseconds              *float64
	Failure                                   observability.Detail
	CaptureFinalizeMilliseconds               float64
	Preflight                                 bool
}

type Capture interface {
	Headers(string, http.Header)
	Request([]byte)
	Response(int, http.Header)
	Body([]byte)
	Complete(string, int, string, time.Duration)
}

type Handler struct {
	Store        RouteStore
	Policy       func() contracts.Policy
	Snapshot     func() (contracts.Policy, map[string]struct{})
	Enabled      func() bool
	Bypass       func(string) bool
	DeviceID     func() string
	UserID       func(string) string
	GatewayKey   []byte
	Transport    http.RoundTripper
	StartCapture func(Record) Capture
	Observe      func(Record, int, string, time.Duration)
}

func ForwardTransport() *http.Transport {
	return &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true, DisableCompression: true, MaxIdleConns: 64, MaxIdleConnsPerHost: 64,
		IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 15 * time.Second, ExpectContinueTimeout: time.Second}
}

var defaultForwardTransport = http.RoundTripper(ForwardTransport())

// A response buffer belongs to one handler until all forwarding and capture
// writes finish. Pooling avoids allocating 64 KiB for every streamed request.
var responseBuffers = sync.Pool{New: func() any {
	b := make([]byte, 64*1024)
	return &b
}}

func UUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	s := hex.EncodeToString(b[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}

func ValidRouteID(id string) bool {
	if len(id) != 22 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func Target(original, suffix, query string, policy contracts.Policy) (*url.URL, error) {
	base, err := url.Parse(original)
	if err != nil || base.Host == "" || base.User != nil || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, fmt.Errorf("invalid original URL")
	}
	target := *base
	if strings.EqualFold(policy.RouteMode, "fixedGateway") {
		origin := ""
		if policy.GatewayOrigin != nil {
			origin = *policy.GatewayOrigin
		}
		g, e := url.Parse(origin)
		if e != nil || g.Host == "" || g.User != nil || g.RawQuery != "" || g.Fragment != "" || (g.Path != "" && g.Path != "/") || (g.Scheme != "https" && !(g.Scheme == "http" && policy.AllowInsecureGateway)) {
			return nil, fmt.Errorf("invalid gateway origin")
		}
		target.Scheme = g.Scheme
		target.Host = g.Host
	}
	escaped := "/" + strings.Trim(strings.Trim(base.EscapedPath(), "/")+"/"+strings.Trim(suffix, "/"), "/")
	decoded, err := url.PathUnescape(escaped)
	if err != nil {
		return nil, err
	}
	target.Path = decoded
	target.RawPath = escaped
	target.RawQuery = query
	target.ForceQuery = false
	target.Fragment = ""
	return &target, nil
}

// DSH's direct DeepSeek adapter adds /v1 even to the local route URL.
// Keep the original URL intact for policy checks, restoration and HMAC.
func routeTarget(route contracts.Route, suffix, query string, policy contracts.Policy) (*url.URL, error) {
	if route.AgentType == 11 && strings.HasPrefix(route.ProviderID, "dsh:messages:deepseek:") {
		base, err := url.Parse(route.OriginalBaseURL)
		if err == nil && strings.HasSuffix(strings.TrimRight(base.Path, "/"), "/v1") {
			suffix = strings.TrimPrefix(suffix, "/")
			if suffix == "v1" {
				suffix = ""
			} else if strings.HasPrefix(suffix, "v1/") {
				suffix = strings.TrimPrefix(suffix, "v1/")
			}
		}
	}
	return Target(route.OriginalBaseURL, suffix, query, policy)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	record := Record{RequestID: UUID(), Started: time.Now().UTC(), Inbound: r.URL.RequestURI(), Preflight: true}
	var capture Capture
	status, outcome, code := 0, "PROXY_INTERNAL_ERROR", ""
	defer func() {
		elapsed := time.Since(record.Started)
		if capture != nil {
			if diagnostic, ok := capture.(interface{ Diagnostic(observability.Detail) }); ok {
				diagnostic.Diagnostic(record.Failure)
			}
			finalize := time.Now()
			capture.Complete(outcome, status, code, elapsed)
			record.CaptureFinalizeMilliseconds = float64(time.Since(finalize).Microseconds()) / 1000
		}
		if h.Observe != nil {
			h.Observe(record, status, outcome, elapsed)
		}
	}()
	reject := func(httpStatus int, external, reason, message string, err error) {
		status, outcome, code = httpStatus, external, external
		record.Failure = observability.Classify(err)
		record.Failure.Stage, record.Failure.Code = "preflight", reason
		if record.Failure.Class == "" {
			record.Failure.Class = reason
		}
		writeError(w, status, external, message)
	}
	if r.Method != "GET" && r.Method != "POST" && r.Method != "PUT" && r.Method != "DELETE" && r.Method != "PATCH" && r.Method != "OPTIONS" && r.Method != "HEAD" {
		reject(405, "METHOD_NOT_ALLOWED", "METHOD_NOT_ALLOWED", "The proxy method is not supported.", nil)
		return
	}
	path := r.URL.EscapedPath()
	if !strings.HasPrefix(path, "/r/") {
		reject(404, "ROUTE_NOT_FOUND", "ROUTE_NOT_FOUND", "The local route was not found.", nil)
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(path, "/r/"), "/", 2)
	id := parts[0]
	if !ValidRouteID(id) {
		reject(404, "ROUTE_NOT_FOUND", "ROUTE_NOT_FOUND", "The local route was not found.", nil)
		return
	}
	route, err := h.Store.FindRoute(r.Context(), id)
	if err != nil {
		reject(500, "PROXY_INTERNAL_ERROR", "ROUTE_STATE_READ_FAILED", "Route state could not be read.", err)
		return
	}
	if route == nil {
		reject(404, "ROUTE_NOT_FOUND", "ROUTE_NOT_FOUND", "The local route was not found.", nil)
		return
	}
	record.Route = *route
	var policy contracts.Policy
	var allowlist map[string]struct{}
	if h.Snapshot != nil {
		policy, allowlist = h.Snapshot()
	} else {
		policy = h.Policy()
	}
	if !policy.Enabled || (h.Enabled != nil && !h.Enabled()) {
		reject(500, "PROXY_INTERNAL_ERROR", "PROXY_DISABLED", "The local proxy failed.", nil)
		return
	}
	bypass := false
	if allowlist != nil {
		normalized, e := protocol.NormalizeBaseURL(route.OriginalBaseURL)
		if e == nil {
			_, bypass = allowlist[normalized]
		}
	} else if h.Bypass != nil {
		bypass = h.Bypass(route.OriginalBaseURL)
	}
	if bypass {
		reject(409, "BASE_URL_ALLOWLIST_BYPASS", "BASE_URL_ALLOWLIST_BYPASS", "The configured BaseURL must bypass the endpoint proxy.", nil)
		return
	}
	suffix := ""
	if len(parts) == 2 {
		suffix = parts[1]
	}
	target, err := routeTarget(*route, suffix, r.URL.RawQuery, policy)
	if err != nil {
		reject(502, "PROXY_TARGET_INVALID", "PROXY_TARGET_INVALID", "The route target is invalid.", err)
		return
	}
	user := route.UserSID
	if h.UserID != nil {
		user = h.UserID(route.UserSID)
	} else if strings.HasPrefix(user, "macos:") {
		user = strings.TrimPrefix(user, "macos:")
	}
	agent, surface := Classify(*route, r.UserAgent())
	record.UserID, record.Agent, record.Surface, record.Outbound = user, agent, surface, target.String()
	// HTTP/1 response Flush otherwise closes the inbound body while Transport
	// may still be checking the forwarded Content-Length in its write goroutine.
	// HTTP/2 is already full duplex and reports ErrNotSupported here.
	if err := http.NewResponseController(w).EnableFullDuplex(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		reject(500, "PROXY_STREAM_SETUP_FAILED", "PROXY_STREAM_SETUP_FAILED", "The local stream could not be prepared.", err)
		return
	}
	record.Preflight = false
	if h.StartCapture != nil {
		capture = h.StartCapture(record)
	}
	out := r.Clone(r.Context())
	out.URL = target
	out.RequestURI = ""
	out.Host = target.Host
	out.Close = false
	out.Header = r.Header.Clone()
	strip(out.Header, true)
	if strings.EqualFold(policy.RouteMode, "fixedGateway") {
		// This name no longer shares the X-SF-AI-* prefix. Never trust a caller's
		// user identity; gateway metadata comes exclusively from the local route.
		out.Header.Del("X-Sf-Userid")
		h.gatewayHeaders(out, record, target)
	}
	if capture != nil {
		capture.Headers("Inbound request headers", r.Header)
		capture.Headers("Outbound request headers", out.Header)
		if out.Body != nil {
			out.Body = &capturingBody{ReadCloser: out.Body, write: capture.Request}
		}
	}
	transport := h.Transport
	if transport == nil {
		transport = defaultForwardTransport
	}
	mark(capture, "GatewayRequestStartedAtUtc")
	gatewayStarted := time.Now()
	response, err := transport.RoundTrip(out)
	if err != nil {
		record.Failure = observability.Classify(err)
		record.Failure.Stage = networkStage(record.Failure, "upstream_headers")
		if r.Context().Err() != nil {
			outcome = "CLIENT_CANCELLED"
			code = outcome
			return
		}
		status = 502
		outcome = "GATEWAY_CONNECTION_FAILED"
		code = outcome
		writeError(w, status, code, "The upstream connection failed.")
		return
	}
	defer response.Body.Close()
	roundTrip := float64(time.Since(gatewayStarted).Microseconds()) / 1000
	record.GatewayRoundTripMilliseconds = &roundTrip
	mark(capture, "GatewayResponseHeadersReceivedAtUtc")
	if capture != nil {
		capture.Response(response.StatusCode, response.Header)
	}
	if response.StatusCode >= 300 && response.StatusCode <= 399 {
		status = 502
		outcome = "UPSTREAM_REDIRECT_BLOCKED"
		code = outcome
		record.Failure = observability.Detail{Stage: "upstream_headers", Class: "HTTP_REDIRECT", HTTPStatus: response.StatusCode, Code: code}
		writeError(w, status, code, "The upstream returned a redirect, which the proxy does not follow.")
		return
	}
	headers := response.Header.Clone()
	strip(headers, false)
	for name, values := range headers {
		w.Header()[name] = values
	}
	status = response.StatusCode
	w.WriteHeader(status)
	pooled := responseBuffers.Get().(*[]byte)
	defer responseBuffers.Put(pooled)
	buffer := *pooled
	first := true
	for {
		n, readErr := response.Body.Read(buffer)
		if n > 0 {
			if first {
				mark(capture, "AgentResponseStartedAtUtc")
				first = false
			}
			if _, err = w.Write(buffer[:n]); err != nil {
				record.Failure = observability.Classify(err)
				record.Failure.Stage = "client_write"
				outcome = "CLIENT_CANCELLED"
				code = outcome
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			if capture != nil {
				capture.Body(buffer[:n])
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				record.Failure = observability.Classify(readErr)
				record.Failure.Stage = "upstream_stream"
				outcome = "GATEWAY_STREAM_FAILED"
				if r.Context().Err() != nil {
					outcome = "CLIENT_CANCELLED"
				}
				code = outcome
				panic(http.ErrAbortHandler)
			}
			break
		}
	}
	outcome = "SUCCESS"
	if status < 200 || status > 299 {
		outcome = "GATEWAY_HTTP_ERROR"
		code = outcome
		record.Failure = observability.Detail{Stage: "upstream_response", Class: "HTTP_ERROR", HTTPStatus: status, Code: code}
	}
}

func networkStage(d observability.Detail, fallback string) string {
	if strings.HasPrefix(d.Class, "DNS_") {
		return "dns"
	}
	if strings.HasPrefix(d.Class, "TLS_") {
		return "tls"
	}
	if d.Class == "CONNECTION_REFUSED" || d.Class == "CONNECTION_RESET" {
		return "connect"
	}
	return fallback
}

func mark(c Capture, stage string) {
	if t, ok := c.(interface{ Timing(string, time.Time) }); ok {
		t.Timing(stage, time.Now().UTC())
	}
}

type capturingBody struct {
	io.ReadCloser
	write func([]byte)
}

func (b *capturingBody) Read(p []byte) (int, error) {
	n, e := b.ReadCloser.Read(p)
	if n > 0 {
		b.write(p[:n])
	}
	return n, e
}

func strip(headers http.Header, request bool) {
	for _, value := range headers.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			headers.Del(strings.TrimSpace(name))
		}
	}
	for name := range headers {
		lower := strings.ToLower(name)
		switch lower {
		case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade":
			headers.Del(name)
		}
		if request && (lower == "host" || strings.HasPrefix(lower, "x-sf-ai-")) {
			headers.Del(name)
		}
	}
}

func (h *Handler) gatewayHeaders(out *http.Request, rec Record, target *url.URL) {
	original, _ := url.Parse(rec.Route.OriginalBaseURL)
	now := time.Now().UTC()
	device := ""
	if h.DeviceID != nil {
		device = h.DeviceID()
	}
	values := []string{"v1", rec.RequestID, strconv.FormatInt(now.Unix(), 10), device, rec.UserID, rec.Route.UserSID, rec.Agent, rec.Surface, rec.Route.ProviderID, rec.Route.OriginalBaseURL, original.Host, strings.ToUpper(out.Method), target.RequestURI()}
	names := []string{"X-Request-Id", "X-SF-AI-Timestamp", "X-SF-AI-Device-Id", "X-Sf-Userid", "X-SF-AI-User-Sid", "X-SF-AI-Agent", "X-SF-AI-Agent-Surface", "X-SF-AI-Provider-Id", "X-SF-AI-Original-Base-Url", "X-SF-AI-Original-Authority"}
	for i, name := range names {
		out.Header.Set(name, values[i+1])
	}
	if len(h.GatewayKey) >= 32 {
		mac := hmac.New(sha256.New, h.GatewayKey)
		mac.Write([]byte(strings.Join(values, "\n")))
		out.Header.Set("X-SF-AI-Signature", "v1:"+base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	}
}

func Classify(route contracts.Route, ua string) (string, string) {
	agent := "UnknownCandidate"
	switch route.AgentType {
	case 0, 8, 9, 10:
		agent = "ClaudeCode"
	case 1, 6, 7:
		agent = "Codex"
	case 2:
		agent = "QoderCli"
	case 3:
		agent = "QoderIde"
	case 11:
		agent = "DeepSeekHarness"
	case 4:
		agent = "CcSwitch"
		if strings.HasPrefix(strings.ToLower(route.ProviderID), "claude:") {
			agent = "ClaudeCode"
		}
		if strings.HasPrefix(strings.ToLower(route.ProviderID), "codex:") {
			agent = "Codex"
		}
	}
	u := strings.ToLower(ua)
	surface := "unknown"
	switch {
	case strings.Contains(u, "vscode"), strings.Contains(u, "jetbrains"), strings.Contains(u, "cursor"):
		surface = "ide"
	case strings.Contains(u, "desktop"), strings.Contains(u, "electron"):
		surface = "desktop"
	case strings.Contains(u, "codex_cli"), strings.Contains(u, "claude-code-cli"):
		surface = "cli"
	case route.AgentType == 6 || route.AgentType == 9:
		surface = "ide"
	case route.AgentType == 7 || route.AgentType == 10:
		surface = "desktop"
	case route.AgentType == 11:
		surface = "cli"
	}
	return agent, surface
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}

package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AccountListeners preserve an origin for SDKs that resolve /models at the
// origin root. Every listener is bound to exactly one persisted route.
type AccountListeners struct {
	mu        sync.Mutex
	handler   http.Handler
	servers   map[string]*http.Server
	listeners map[string]net.Listener
	origins   map[string]string
}

func NewAccountListeners(handler http.Handler) *AccountListeners {
	return &AccountListeners{handler: handler, servers: map[string]*http.Server{}, listeners: map[string]net.Listener{}, origins: map[string]string{}}
}

func (a *AccountListeners) Ensure(id, previous string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !ValidRouteID(id) {
		return "", errors.New("ACCOUNT_ROUTE_INVALID")
	}
	if origin := a.origins[id]; origin != "" {
		if previous != "" && previous != origin {
			return "", errors.New("ACCOUNT_ORIGIN_CHANGED")
		}
		return origin, nil
	}
	address := "127.0.0.1:0"
	if previous != "" {
		u, err := url.Parse(previous)
		if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Port() == "0" || u.Port() == "18080" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return "", errors.New("ACCOUNT_ORIGIN_INVALID")
		}
		address = u.Host
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1024 || port > 65535 {
			return "", errors.New("ACCOUNT_ORIGIN_INVALID")
		}
	}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return "", errors.New("ACCOUNT_LISTENER_UNAVAILABLE")
	}
	origin := "http://" + listener.Addr().String()
	server := &http.Server{ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != listener.Addr().String() || (r.URL.Path != "/models" && !strings.HasPrefix(r.URL.Path, "/anthropic/")) {
			http.NotFound(w, r)
			return
		}
		copy := r.Clone(r.Context())
		target := *r.URL
		target.Path = "/r/" + id + r.URL.Path
		target.RawPath = "/r/" + id + r.URL.EscapedPath()
		copy.URL = &target
		copy.RequestURI = target.RequestURI()
		a.handler.ServeHTTP(w, copy)
	})
	a.servers[id], a.origins[id] = server, origin
	a.listeners[id] = listener
	go server.Serve(listener)
	return origin, nil
}

func (a *AccountListeners) Prune(valid map[string]bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, server := range a.servers {
		if !valid[id] {
			a.listeners[id].Close()
			server.Close()
			delete(a.servers, id)
			delete(a.listeners, id)
			delete(a.origins, id)
		}
	}
}

func (a *AccountListeners) Close() {
	a.mu.Lock()
	servers := a.servers
	for _, listener := range a.listeners {
		listener.Close()
	}
	a.servers, a.origins = map[string]*http.Server{}, map[string]string{}
	a.listeners = map[string]net.Listener{}
	a.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, server := range servers {
		if server.Shutdown(ctx) != nil {
			server.Close()
		}
	}
}

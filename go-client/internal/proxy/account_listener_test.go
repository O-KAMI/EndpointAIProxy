package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestAccountOriginPreservesRootPathsAndIsolation(t *testing.T) {
	seen := make(chan string, 4)
	listeners := NewAccountListeners(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.URL.RequestURI()
		io.WriteString(w, "synthetic")
	}))
	defer listeners.Close()
	id := "abcdefghijklmnopqrstuv"
	origin, err := listeners.Ensure(id, "")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	for _, path := range []string{"/models", "/anthropic/v1/messages?x=a%2Fb"} {
		response, err := client.Get(origin + path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != 200 || <-seen != "/r/"+id+path {
			t.Fatal("account path was changed")
		}
	}
	response, err := client.Get(origin + "/unrelated")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal("unscoped endpoint accepted")
	}
	same, err := listeners.Ensure(id, origin)
	if err != nil || same != origin {
		t.Fatal("origin changed", err)
	}
	for _, bad := range []string{"http://0.0.0.0:18181", "http://127.0.0.1:18080", origin + "/path"} {
		if _, err := listeners.Ensure("ABCDEFGHIJKLMNOPQRSTUV", bad); err == nil {
			t.Fatal("unsafe origin accepted")
		}
	}
	listeners.Prune(map[string]bool{})
	restored, err := listeners.Ensure(id, origin)
	if err != nil || restored != origin || !strings.HasPrefix(restored, "http://127.0.0.1:") {
		t.Fatal("origin was not recoverable", err)
	}
}

package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEncryptedTransportRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/transport/v1" {
			t.Errorf("outer request: %s %s", r.Method, r.URL.Path)
		}
		var envelope Envelope
		if e := json.NewDecoder(r.Body).Decode(&envelope); e != nil {
			t.Error(e)
			w.WriteHeader(500)
			return
		}
		b, e := Open(key, "synthetic", envelope.RequestID, envelope, "request")
		if e != nil {
			t.Error(e)
			w.WriteHeader(500)
			return
		}
		var inner InnerRequest
		if e = json.Unmarshal(b, &inner); e != nil {
			t.Error(e)
			w.WriteHeader(500)
			return
		}
		if inner.Method != "PUT" || inner.Path != "/api/test" || inner.Query != "a=1" || inner.Token != "synthetic-token" || inner.Body != base64.StdEncoding.EncodeToString([]byte("body")) {
			t.Errorf("incorrect authenticated inner request: %+v", inner)
		}
		b, e = json.Marshal(InnerResponse{Status: 401, Body: base64.StdEncoding.EncodeToString([]byte("authenticated denial")), Headers: map[string]string{"X-SF-Policy-Signature": "v1:synthetic", "Set-Cookie": "must-drop"}})
		if e != nil {
			t.Error(e)
		}
		out, e := Seal(key, "synthetic", envelope.RequestID, b, "response")
		if e != nil {
			t.Error(e)
		}
		json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	client := &http.Client{Transport: &Transport{MasterKey: key, KeyID: "synthetic", ServerOrigin: server.URL}}
	req, e := http.NewRequest("PUT", server.URL+"/api/test?a=1", strings.NewReader("body"))
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("Authorization", "Bearer synthetic-token")
	res, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	b, e := io.ReadAll(res.Body)
	if e != nil {
		t.Fatal(e)
	}
	if res.StatusCode != 401 || string(b) != "authenticated denial" || res.Header.Get("X-SF-Policy-Signature") == "" || res.Header.Get("Set-Cookie") != "" {
		t.Fatalf("incorrect authenticated response %d %q %+v", res.StatusCode, b, res.Header)
	}
}
func TestOuterUnauthorizedIsTransportFailure(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	defer s.Close()
	client := &http.Client{Transport: &Transport{MasterKey: make([]byte, 32), KeyID: "synthetic", ServerOrigin: s.URL}}
	res, e := client.Get(s.URL + "/api/policy")
	if e == nil {
		res.Body.Close()
		t.Fatal("outer 401 became trusted business response")
	}
}

package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestCredentialsAndOverrides(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	data := map[string]string{"origin": "http://control.example.invalid:8080", "clientToken": strings.Repeat("x", 16), "policyHmacKey": key, "transportKey": key, "keyId": "v1"}
	raw, _ := json.Marshal(data)
	v, e := credentials(raw)
	if e != nil || len(v) != 6 {
		t.Fatal(e)
	}
	data["extra"] = "no"
	raw, _ = json.Marshal(data)
	if _, e = credentials(raw); e == nil {
		t.Fatal("extra field accepted")
	}
	if !controlOverride("sf_proxy_control_token=secret") || controlOverride("PATH=test") {
		t.Fatal("override filtering")
	}
}
func TestOrigins(t *testing.T) {
	for _, raw := range []string{"http://control.example.test:8080", "http://127.0.0.1", "http://[::1]:8080/"} {
		if !validOrigin(raw) {
			t.Fatalf("valid origin rejected: %s", raw)
		}
	}
	for _, raw := range []string{"https://host", "http://user:pass@host", "http://host/path", "http://host?token=secret", "http://host#fragment", "http://host:", "http://host:70000", "http://-bad.test", "http://host/\n"} {
		if validOrigin(raw) {
			t.Fatalf("unsafe origin accepted: %s", raw)
		}
	}
}

package main

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestCredentialsAndOverrides(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	data := map[string]string{"origin": "http://control.example.invalid:8080", "clientToken": strings.Repeat("x", 16), "policyHmacKey": key, "transportKey": key, "keyId": "v1"}
	raw, _ := json.Marshal(data)
	v, e := credentials(raw)
	if e != nil || len(v) != 7 {
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

func TestCredentialsRequireExactlyOnePolicyVerificationMode(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	data := map[string]string{"origin": "http://control.example.invalid:8080", "clientToken": strings.Repeat("x", 16), "policyPublicKey": key, "transportKey": key, "keyId": "v1"}
	raw, _ := json.Marshal(data)
	settings, err := credentials(raw)
	if err != nil || settings["ControlPolicyPublicKey"] != key || settings["ControlPolicyHmacKey"] != "" {
		t.Fatal("public-key credential rejected", err)
	}
	data["policyHmacKey"] = key
	raw, _ = json.Marshal(data)
	if _, err := credentials(raw); err == nil {
		t.Fatal("ambiguous policy credentials accepted")
	}
	delete(data, "policyHmacKey")
	data["policyPublicKey"] = base64.StdEncoding.EncodeToString(make([]byte, 31))
	raw, _ = json.Marshal(data)
	if _, err := credentials(raw); err == nil {
		t.Fatal("short public key accepted")
	}
	if !controlOverride("SF_PROXY_CONTROL_POLICY_PUBLIC_KEY=stale") {
		t.Fatal("public key override not removed during upgrade")
	}
}
func TestOrigins(t *testing.T) {
	for _, raw := range []string{"http://control.example.test:8080", "http://127.0.0.1", "http://[::1]:8080/", "https://host"} {
		if !validOrigin(raw) {
			t.Fatalf("valid origin rejected: %s", raw)
		}
	}
	for _, raw := range []string{"HTTPS://host", "http://user:pass@host", "http://host/path", "http://host?token=secret", "http://host#fragment", "http://host:", "http://host:70000", "http://-bad.test", "http://host/\n"} {
		if validOrigin(raw) {
			t.Fatalf("unsafe origin accepted: %s", raw)
		}
	}
}

func TestHTTPSCredentialsRequirePin(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	data := map[string]string{"origin": "https://control.example.test", "clientToken": strings.Repeat("x", 16), "policyPublicKey": key, "transportKey": key, "keyId": "v1"}
	check := func(valid bool) {
		raw, _ := json.Marshal(data)
		settings, err := credentials(raw)
		if (err == nil) != valid {
			t.Fatalf("valid=%v error=%v", valid, err)
		}
		if valid && settings["ControlServerCertificateSpkiSha256"] != data["certificateSpkiSha256"] {
			t.Fatal("pin not propagated")
		}
	}
	check(false)
	data["certificateSpkiSha256"] = base64.StdEncoding.EncodeToString(make([]byte, 31))
	check(false)
	data["certificateSpkiSha256"] = key
	check(true)
	data["origin"] = "http://control.example.test"
	check(false)
	delete(data, "certificateSpkiSha256")
	check(true)
}

func TestServiceEnvironmentSurvivesServiceRecreation(t *testing.T) {
	previous := []string{"SF_PROXY_EXCLUDE_CODEX=true", "SF_PROXY_GATEWAY_HMAC_KEY=synthetic-key", "SF_PROXY_CONTROL_TOKEN=stale", "sf_proxy_allow_insecure_control_server=true"}
	want := []string{"SF_PROXY_EXCLUDE_CODEX=true", "SF_PROXY_GATEWAY_HMAC_KEY=synthetic-key"}
	if got := serviceEnvironment(previous, nil); !reflect.DeepEqual(got, want) {
		t.Fatal("deleted service key lost non-control settings or retained control overrides")
	}
	current := []string{"sf_proxy_exclude_codex=false", "SF_PROXY_CONTROL_ORIGIN=http://stale.invalid", "OTHER=value"}
	want = []string{"sf_proxy_exclude_codex=false", "SF_PROXY_GATEWAY_HMAC_KEY=synthetic-key", "OTHER=value"}
	if got := serviceEnvironment(previous, current); !reflect.DeepEqual(got, want) {
		t.Fatal("explicit current settings must win case-insensitively without losing unrelated snapshot settings")
	}
}

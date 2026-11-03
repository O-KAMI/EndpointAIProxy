package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var controlNames = []string{"ControlServerOrigin", "ControlEnrollmentToken", "ControlPolicyHmacKey", "ControlPolicyPublicKey", "ControlTransportKey", "ControlTransportKeyId", "ControlServerCertificateSpkiSha256"}

func credentials(raw []byte) (map[string]string, error) {
	var values map[string]string
	if e := json.Unmarshal(raw, &values); e != nil {
		return nil, errors.New("invalid credentials")
	}
	names := []string{"origin", "clientToken", "transportKey", "keyId"}
	if _, ok := values["policyPublicKey"]; ok {
		names = append(names, "policyPublicKey")
	} else {
		names = append(names, "policyHmacKey")
	}
	if strings.HasPrefix(values["origin"], "https://") {
		names = append(names, "certificateSpkiSha256")
	}
	if len(values) != len(names) {
		return nil, errors.New("invalid credentials")
	}
	for _, n := range names {
		if _, ok := values[n]; !ok {
			return nil, errors.New("invalid credentials")
		}
	}
	transport, e := base64.StdEncoding.DecodeString(values["transportKey"])
	hmac, he := base64.StdEncoding.DecodeString(values["policyHmacKey"])
	public, pe := base64.StdEncoding.DecodeString(values["policyPublicKey"])
	pin, pinErr := base64.StdEncoding.DecodeString(values["certificateSpkiSha256"])
	keyOK := (values["policyPublicKey"] == "" && he == nil && len(hmac) >= 32) || (values["policyHmacKey"] == "" && pe == nil && len(public) == 32)
	pinOK := !strings.HasPrefix(values["origin"], "https://") || (pinErr == nil && len(pin) == 32)
	if !validOrigin(values["origin"]) || !regexp.MustCompile(`^[A-Za-z0-9_-]{16,}$`).MatchString(values["clientToken"]) || !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(values["keyId"]) || e != nil || len(transport) != 32 || !keyOK || !pinOK {
		return nil, errors.New("invalid credentials")
	}
	return map[string]string{"ControlServerOrigin": values["origin"], "ControlEnrollmentToken": values["clientToken"], "ControlPolicyHmacKey": values["policyHmacKey"], "ControlPolicyPublicKey": values["policyPublicKey"], "ControlTransportKey": values["transportKey"], "ControlTransportKeyId": values["keyId"], "ControlServerCertificateSpkiSha256": values["certificateSpkiSha256"]}, nil
}
func validOrigin(raw string) bool {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return false
	}
	u, e := url.Parse(raw)
	if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(raw, "\r\n\t #?") {
		return false
	}
	host := u.Hostname()
	if net.ParseIP(host) == nil {
		if len(host) > 253 {
			return false
		}
		for _, label := range strings.Split(host, ".") {
			if !regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`).MatchString(label) {
				return false
			}
		}
	}
	if port := u.Port(); port != "" {
		p, e := strconv.Atoi(port)
		if e != nil || p < 1 || p > 65535 {
			return false
		}
	}
	return !strings.HasSuffix(u.Host, ":")
}
func controlOverride(line string) bool {
	name, _, _ := strings.Cut(line, "=")
	name = strings.ToUpper(name)
	if name == "SF_PROXY_ALLOW_INSECURE_CONTROL_SERVER" {
		return true
	}
	for _, suffix := range []string{"ORIGIN", "TOKEN", "HMAC_KEY", "POLICY_PUBLIC_KEY", "TRANSPORT_KEY", "TRANSPORT_KEY_ID", "SERVER_CERTIFICATE_SPKI_SHA256"} {
		if name == "SF_PROXY_CONTROL_"+suffix {
			return true
		}
	}
	return false
}

// Major upgrades can delete the service registry key before recreating it.
// Preserve non-control settings from the snapshot; explicit current settings win.
func serviceEnvironment(previous, current []string) []string {
	out := []string{}
	indexes := map[string]int{}
	for _, source := range [][]string{previous, current} {
		for _, line := range source {
			if controlOverride(line) {
				continue
			}
			name, _, _ := strings.Cut(line, "=")
			name = strings.ToUpper(name)
			if index, exists := indexes[name]; exists {
				out[index] = line
			} else {
				indexes[name] = len(out)
				out = append(out, line)
			}
		}
	}
	return out
}

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

var controlNames = []string{"ControlServerOrigin", "ControlEnrollmentToken", "ControlPolicyHmacKey", "ControlTransportKey", "ControlTransportKeyId", "ControlServerCertificateSpkiSha256"}

func credentials(raw []byte) (map[string]string, error) {
	var values map[string]string
	if e := json.Unmarshal(raw, &values); e != nil {
		return nil, errors.New("invalid credentials")
	}
	names := []string{"origin", "clientToken", "policyHmacKey", "transportKey", "keyId"}
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
	if !validOrigin(values["origin"]) || !regexp.MustCompile(`^[A-Za-z0-9_-]{16,}$`).MatchString(values["clientToken"]) || !regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`).MatchString(values["keyId"]) || e != nil || len(transport) != 32 || he != nil || len(hmac) < 32 {
		return nil, errors.New("invalid credentials")
	}
	return map[string]string{"ControlServerOrigin": values["origin"], "ControlEnrollmentToken": values["clientToken"], "ControlPolicyHmacKey": values["policyHmacKey"], "ControlTransportKey": values["transportKey"], "ControlTransportKeyId": values["keyId"], "ControlServerCertificateSpkiSha256": ""}, nil
}
func validOrigin(raw string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(raw, "\r\n\t #?") {
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
	for _, suffix := range []string{"ORIGIN", "TOKEN", "HMAC_KEY", "TRANSPORT_KEY", "TRANSPORT_KEY_ID", "SERVER_CERTIFICATE_SPKI_SHA256"} {
		if name == "SF_PROXY_CONTROL_"+suffix {
			return true
		}
	}
	return false
}

package protocol

import (
	"endpointai/client/internal/contracts"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"golang.org/x/net/idna"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

type ValidationError struct{ Code, Message string }

func (e *ValidationError) Error() string { return e.Code + ": " + e.Message }
func invalid(code, message string) error { return &ValidationError{code, message} }
func ValidatePolicy(p contracts.Policy) error {
	if p.SchemaVersion != 1 {
		return invalid("POLICY_SCHEMA_UNSUPPORTED", "Only policy schema version 1 is supported.")
	}
	id, e := uuid.Parse(p.ServerInstanceID)
	if e != nil || id == uuid.Nil || p.PolicyVersion < 1 {
		return invalid("POLICY_IDENTITY_INVALID", "The policy server identity and version are required.")
	}
	if p.PollIntervalSeconds < 15 || p.PollIntervalSeconds > 3600 || p.HeartbeatIntervalSeconds < 15 || p.HeartbeatIntervalSeconds > 3600 {
		return invalid("POLICY_INTERVAL_INVALID", "Policy intervals must be between 15 and 3600 seconds.")
	}
	if _, e = NormalizeAllowlist(p.AllowlistedBaseURLs); e != nil {
		return invalid("POLICY_ALLOWLIST_INVALID", e.Error())
	}
	if p.RouteMode != "passthroughOriginal" && p.RouteMode != "fixedGateway" {
		return invalid("POLICY_ROUTE_MODE_INVALID", "Unknown route mode.")
	}
	if p.RouteMode == "fixedGateway" {
		if p.GatewayOrigin == nil {
			return invalid("POLICY_GATEWAY_INVALID", "Missing gateway origin")
		}
		u, e := url.Parse(*p.GatewayOrigin)
		if e != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "https" && !(p.AllowInsecureGateway && u.Scheme == "http")) || (u.Path != "" && u.Path != "/") || strings.ContainsAny(*p.GatewayOrigin, "?#") {
			return invalid("POLICY_GATEWAY_INVALID", "Fixed gateway mode requires a valid origin; HTTP must be explicitly allowed by policy.")
		}
		if _, e = NormalizeBaseURL(*p.GatewayOrigin); e != nil {
			return invalid("POLICY_GATEWAY_INVALID", e.Error())
		}
	}
	return nil
}

var hostPattern = regexp.MustCompile(`^[a-z0-9_.-]+$`)

func hex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }
func normalizeEscapes(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && (i+2 >= len(s) || !hex(s[i+1]) || !hex(s[i+2])) {
			out.WriteString("%25")
		} else {
			out.WriteByte(s[i])
		}
	}
	return out.String()
}

// legacyIPv4 matches .NET Uri's compact and hexadecimal IPv4 host parsing.
func legacyIPv4(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return host
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		base := 10
		if strings.HasPrefix(strings.ToLower(p), "0x") {
			base = 16
			p = p[2:]
		} else if len(p) > 1 && p[0] == '0' {
			base = 8
		}
		v, e := strconv.ParseUint(p, base, 32)
		if e != nil {
			return host
		}
		nums[i] = v
	}
	var v uint64
	for i, n := range nums {
		if i < len(nums)-1 {
			if n > 255 {
				return host
			}
			v = v<<8 | n
		} else {
			bits := uint(8 * (5 - len(nums)))
			if n >= (uint64(1) << bits) {
				return host
			}
			v = v<<bits | n
		}
	}
	return fmt.Sprintf("%d.%d.%d.%d", v>>24, (v>>16)&255, (v>>8)&255, v&255)
}
func NormalizeBaseURL(value string) (string, error) {
	if strings.TrimSpace(value) == "" || utf8.RuneCountInString(value) > 2048 {
		return "", errors.New("invalid Base URL length")
	}
	text := strings.TrimSpace(value)
	if strings.ContainsAny(text, "?#\\") || strings.IndexFunc(text, func(r rune) bool { return r < 32 }) >= 0 {
		return "", errors.New("Base URL contains forbidden characters")
	}
	u, e := url.Parse(normalizeEscapes(text))
	if e != nil {
		return "", e
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Hostname() == "" || u.User != nil {
		return "", errors.New("Base URL must be absolute HTTP(S) without credentials")
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		ip := net.ParseIP(host)
		if ip == nil {
			return "", errors.New("invalid IPv6 host")
		}
		host = "[" + ip.String() + "]"
	} else {
		host, e = idna.Punycode.ToASCII(host)
		if e != nil {
			return "", e
		}
		host = strings.ToLower(host)
		if !hostPattern.MatchString(host) {
			return "", errors.New("invalid hostname")
		}
		host = legacyIPv4(host)
	}
	port := u.Port()
	if port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 0 || n > 65535 {
			return "", errors.New("invalid port")
		}
		if !(scheme == "https" && n == 443 || scheme == "http" && n == 80) {
			host += ":" + strconv.Itoa(n)
		}
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	segments := []string{}
	for _, part := range strings.Split(path, "/") {
		dot := strings.ReplaceAll(strings.ReplaceAll(part, "%2e", "."), "%2E", ".")
		if dot == ".." {
			if len(segments) > 0 {
				segments = segments[:len(segments)-1]
			}
		} else if dot != "." {
			segments = append(segments, part)
		}
	}
	path = strings.Join(segments, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return scheme + "://" + host + strings.TrimRight(path, "/"), nil
}
func NormalizeAllowlist(values []string) ([]string, error) {
	if values == nil {
		return nil, nil
	}
	out := []string{}
	seen := map[string]bool{}
	for _, v := range values {
		if len(out) >= 256 {
			return nil, errors.New("Base URL allowlist exceeds 256 entries")
		}
		n, e := NormalizeBaseURL(v)
		if e != nil {
			return nil, e
		}
		if !seen[n] {
			out = append(out, n)
			seen[n] = true
		}
	}
	return out, nil
}

package protocol

import (
	"errors"
	"net"
	"net/url"
	"strings"

	"endpointai/client/internal/contracts"
	"golang.org/x/net/idna"
)

// NormalizeDomain accepts a hostname or IP, never URL paths, ports or wildcards.
func NormalizeDomain(value string) (string, error) {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.String(), nil
	}
	host, err := idna.Lookup.ToASCII(host)
	if err != nil || host == "" || len(host) > 253 {
		return "", errors.New("invalid domain")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid domain label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("domain must not contain a URL, port or wildcard")
			}
		}
	}
	return host, nil
}

func URLDomain(original string) (string, error) {
	u, err := url.Parse(original)
	if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", errors.New("invalid original URL")
	}
	return NormalizeDomain(u.Hostname())
}

func DomainMatches(host, domain string) bool {
	if host == domain {
		return true
	}
	return net.ParseIP(host) == nil && net.ParseIP(domain) == nil && strings.HasSuffix(host, "."+domain)
}

// DomainAllowed uses the compiled canonical set shared by attachment and forwarding.
func DomainAllowed(original string, domains map[string]struct{}) bool {
	host, err := URLDomain(original)
	if err != nil {
		return false
	}
	if _, ok := domains[host]; ok {
		return true
	}
	if net.ParseIP(host) != nil {
		return false
	}
	for i := strings.IndexByte(host, '.'); i >= 0; i = strings.IndexByte(host, '.') {
		host = host[i+1:]
		if net.ParseIP(host) != nil {
			return false
		}
		if _, ok := domains[host]; ok {
			return true
		}
	}
	return false
}

func ResolveRoutingPolicy(original string, policy contracts.Policy) contracts.Policy {
	if policy.SchemaVersion != 2 || len(policy.RoutingRules) == 0 {
		return policy
	}
	host, err := URLDomain(original)
	if err != nil {
		return policy
	}
	best := -1
	var selected *contracts.RoutingRule
	for i := range policy.RoutingRules {
		rule := &policy.RoutingRules[i]
		domain, err := NormalizeDomain(rule.Domain)
		if err == nil && len(domain) > best && DomainMatches(host, domain) {
			best = len(domain)
			selected = rule
		}
	}
	if selected != nil {
		policy.RouteMode = selected.RouteMode
		if selected.GatewayOrigin != nil && *selected.GatewayOrigin != "" {
			policy.GatewayOrigin = selected.GatewayOrigin
		}
	}
	policy.RoutingRules = nil
	return policy
}

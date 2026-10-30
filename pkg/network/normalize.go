package network

import (
	"net"
	"net/url"
	"strings"
)

// NormalizeDomain reduces a user-supplied target to a bare hostname. It accepts
// full URLs ("https://host/path"), host:port, and trailing paths, and it strips
// a leading "www.": Bruter enumerates subdomains, DNS records and certificates
// of the registrable domain, so www.example.com and example.com are the same
// target and keeping the prefix would silently shrink the results.
func NormalizeDomain(input string) string {
	input = strings.TrimSpace(strings.ToLower(input))
	if strings.Contains(input, "://") {
		if u, err := url.Parse(input); err == nil && u.Hostname() != "" {
			input = u.Hostname()
		}
	} else {
		// Strip any path component.
		if i := strings.IndexByte(input, '/'); i >= 0 {
			input = input[:i]
		}
		// Strip a port if present.
		if host, _, err := net.SplitHostPort(input); err == nil {
			input = host
		}
	}
	if stripped := strings.TrimPrefix(input, "www."); stripped != "" {
		input = stripped
	}
	return strings.TrimSuffix(input, ".")
}

// ParseTarget extracts the scheme and authority (host[:port]) to use for the
// HTTP path-fuzzing probes from a user-supplied target. The returned scheme is
// empty when the input did not specify one, signalling the caller to
// auto-detect it. The authority preserves an explicit port so non-standard
// ports (e.g. "http://localhost:8081/") are probed as given rather than
// silently reduced to the default 80/443. Unlike NormalizeDomain it keeps any
// "www." prefix, because the probe must hit the exact host the user named.
func ParseTarget(input string) (scheme, authority string) {
	input = strings.TrimSpace(strings.ToLower(input))
	if input == "" {
		return "", ""
	}
	if strings.Contains(input, "://") {
		if u, err := url.Parse(input); err == nil && u.Hostname() != "" {
			// u.Host includes the port when one was supplied.
			return u.Scheme, u.Host
		}
	}
	// No scheme: drop any path, keep the host[:port] authority.
	if i := strings.IndexByte(input, '/'); i >= 0 {
		input = input[:i]
	}
	return "", input
}

// IsLoopbackAddr reports whether addr is a loopback bind address. An empty
// address means "all interfaces", so it is deliberately not treated as local.
func IsLoopbackAddr(addr string) bool {
	if addr == "localhost" {
		return true
	}
	ip := net.ParseIP(addr)
	return ip != nil && ip.IsLoopback()
}

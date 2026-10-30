package middleware

import (
	"net"
	"net/http"
	"strings"
)

// Guard limits the unauthenticated, actively-scanning server to local access.
//
// Two things make local-only access weaker than it sounds: DNS rebinding lets a
// browser reach a loopback service while presenting an attacker-controlled Host
// header, and a cross-site form can POST to it. So Guard rejects requests whose
// Host is not loopback (or the configured bind address), and mutating /api
// requests that are not JSON — the SPA always sends application/json, which a
// form cannot do without a CORS preflight.
//
// allowRemote disables the Host check for operators who deliberately expose the
// UI with -allow-remote; the JSON requirement stays.
func Guard(bindAddr string, allowRemote bool) func(http.Handler) http.Handler {
	allowed := map[string]bool{
		"":          true,
		"localhost": true,
		"127.0.0.1": true,
		"::1":       true,
	}
	if ip := net.ParseIP(bindAddr); ip != nil && ip.IsLoopback() {
		allowed[strings.ToLower(bindAddr)] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !allowRemote && !allowed[hostOnly(r.Host)] {
				http.Error(w, "bruter only accepts loopback requests; restart with -allow-remote to expose it", http.StatusForbidden)
				return
			}
			if isMutating(r.Method) && strings.HasPrefix(r.URL.Path, "/api/") && !isJSON(r.Header.Get("Content-Type")) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnsupportedMediaType)
				_, _ = w.Write([]byte(`{"error":"Content-Type must be application/json"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// hostOnly strips the port and brackets from a Host header and lower-cases it.
func hostOnly(hostport string) string {
	h := strings.ToLower(strings.TrimSpace(hostport))
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return strings.Trim(h, "[]")
}

func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func isJSON(contentType string) bool {
	// ParseMediaType is avoided deliberately: the client only ever sends
	// application/json (optionally with a charset), so a prefix check is exact
	// enough and tolerant of unusual but harmless parameters.
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "application/json")
}

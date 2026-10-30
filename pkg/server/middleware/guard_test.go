package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// request runs a request through Guard and returns the recorder.
func request(t *testing.T, bindAddr string, allowRemote bool, method, path, host, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	called := false
	h := Guard(bindAddr, allowRemote)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	req.Host = host
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK && !called {
		t.Fatal("a 200 response must come from the inner handler")
	}
	return rec
}

func TestGuardAllowsLoopbackHosts(t *testing.T) {
	for _, host := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080"} {
		rec := request(t, "127.0.0.1", false, http.MethodGet, "/", host, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("host %q should be allowed, got %d", host, rec.Code)
		}
	}
}

func TestGuardRejectsReboundHost(t *testing.T) {
	// DNS rebinding: the request reaches 127.0.0.1 but carries an attacker Host.
	rec := request(t, "127.0.0.1", false, http.MethodPost, "/api/scan", "evil.example:8080", "application/json")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a non-loopback Host must be rejected, got %d", rec.Code)
	}
}

func TestGuardAllowRemoteSkipsHostCheck(t *testing.T) {
	rec := request(t, "0.0.0.0", true, http.MethodGet, "/", "scanner.lan:8080", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("allowRemote should accept any Host, got %d", rec.Code)
	}
}

func TestGuardRequiresJSONForMutations(t *testing.T) {
	// A cross-site form can only send text/plain: that must not reach the API.
	rec := request(t, "127.0.0.1", false, http.MethodPost, "/api/scan", "localhost:8080", "text/plain")
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("non-JSON mutation should be 415, got %d", rec.Code)
	}

	rec = request(t, "127.0.0.1", false, http.MethodPost, "/api/scan", "localhost:8080", "application/json")
	if rec.Code != http.StatusOK {
		t.Fatalf("JSON mutation should pass, got %d", rec.Code)
	}

	rec = request(t, "127.0.0.1", true, http.MethodPost, "/api/crawl", "scanner.lan:8080", "application/json")
	if rec.Code != http.StatusOK {
		t.Fatalf("JSON requirement must hold even with allowRemote, got %d", rec.Code)
	}
}

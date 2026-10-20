package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// get issues a GET against the embedded SPA handler and returns the recorder.
func get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	Handler().ServeHTTP(rec, req)
	return rec
}

// TestHandlerServesEmbeddedAsset verifies a real bundled file (the app logo) is
// served from the embed with its own content type, not swallowed by the SPA
// fallback.
func TestHandlerServesEmbeddedAsset(t *testing.T) {
	rec := get(t, "/bruter-icon.png")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /bruter-icon.png = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "image/png") {
		t.Errorf("content-type = %q, want image/png", ct)
	}
	if rec.Body.Len() == 0 {
		t.Error("expected non-empty image body")
	}
}

// TestHandlerServesIndex verifies the root serves the SPA shell.
func TestHandlerServesIndex(t *testing.T) {
	rec := get(t, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("content-type = %q, want text/html", ct)
	}
}

// TestHandlerSPAFallback verifies that unknown client-routed paths fall back to
// index.html (history-mode routing) rather than 404ing.
func TestHandlerSPAFallback(t *testing.T) {
	for _, p := range []string{"/subdomains", "/whois", "/ssl"} {
		rec := get(t, p)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200 (SPA fallback)", p, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
			t.Errorf("GET %s content-type = %q, want text/html", p, ct)
		}
	}
}

package xss

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// These tests drive the real dalfox binary against a loopback httptest server.
// They are skipped when dalfox is not installed, so CI and contributors without
// the scanner still get a green run; everything is local, no external traffic.

// TestIntegrationUnreachableTargetIsNotClean pins the failure mode where dalfox
// exits 2 and prints valid JSON with zero findings: that is a failed scan, not
// a clean one.
func TestIntegrationUnreachableTargetIsNotClean(t *testing.T) {
	if !Installed() {
		t.Skip("dalfox not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := Scan(ctx, "http://127.0.0.1:9/?q=1", Options{TimeoutSecs: 2, SkipMining: true})
	if err == nil {
		t.Fatalf("an unreachable target was reported as clean: %+v", res)
	}
	if !strings.Contains(err.Error(), "CONNECTION_FAILED") {
		t.Fatalf("error should carry dalfox's reason, got %v", err)
	}
}

// TestIntegrationFindsReflectedXSS checks the happy path end to end: a page that
// reflects a parameter must produce at least one verified finding, and dalfox's
// exit status 1 (findings) must not be treated as an error.
func TestIntegrationFindsReflectedXSS(t *testing.T) {
	if !Installed() {
		t.Skip("dalfox not installed")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body><div>" + r.URL.Query().Get("q") + "</div></body></html>"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	res, err := Scan(ctx, srv.URL+"/?q=test", Options{
		TimeoutSecs:     5,
		Workers:         10,
		SkipMining:      true,
		SkipAST:         true,
		OnlyPoC:         "v",
		ScanTimeoutSecs: 60,
	})
	if err != nil {
		t.Fatalf("scan of a reflected target should succeed, got %v", err)
	}
	if res.Count == 0 {
		t.Fatalf("expected findings on a reflecting page, got %+v (meta=%+v)", res, res.Meta)
	}
	for _, p := range res.PoCs {
		if !strings.EqualFold(p.Type, "V") {
			t.Fatalf("only_poc=v must filter out non-verified findings, got %q", p.Type)
		}
	}
}

// TestIntegrationFindsReflectedXSSInPostBody checks that -d reaches dalfox: the
// parameter exists only in the request body, so a scan that dropped the body or
// moved it into the query string would find nothing.
func TestIntegrationFindsReflectedXSSInPostBody(t *testing.T) {
	if !Installed() {
		t.Skip("dalfox not installed")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Method != http.MethodPost {
			_, _ = w.Write([]byte("<html><body>form</body></html>"))
			return
		}
		_, _ = w.Write([]byte("<html><body><div>" + r.PostFormValue("msg") + "</div></body></html>"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	res, err := Scan(ctx, srv.URL+"/", Options{
		Method:          http.MethodPost,
		Data:            "msg=test",
		TimeoutSecs:     5,
		Workers:         10,
		SkipMining:      true,
		SkipAST:         true,
		OnlyPoC:         "v",
		ScanTimeoutSecs: 60,
	})
	if err != nil {
		t.Fatalf("scan of a reflecting POST target should succeed, got %v", err)
	}
	if res.Count == 0 {
		t.Fatalf("expected findings for a body parameter, got %+v (meta=%+v)", res, res.Meta)
	}
}

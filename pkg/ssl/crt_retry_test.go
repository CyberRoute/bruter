package ssl

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestFetchCrtDataRetriesTransient verifies that 429/5xx responses are retried
// and a subsequent 200 succeeds.
func TestFetchCrtDataRetriesTransient(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			// First two attempts: simulate crt.sh overload.
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"id": 1}]`))
	}))
	defer server.Close()

	origURL, origBackoff := CrtBaseURL, initialBackoff
	CrtBaseURL = server.URL
	initialBackoff = time.Millisecond
	defer func() { CrtBaseURL, initialBackoff = origURL, origBackoff }()

	data, err := FetchCrtData("example.com")
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if len(data) != 1 {
		t.Errorf("expected 1 record, got %d", len(data))
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("expected 3 attempts (2 x 429 + 1 x 200), got %d", got)
	}
}

// TestFetchCrtDataExhaustsRetries verifies that when both crt.sh (persistent
// 503) and the certspotter fallback fail, a clear combined error is returned.
func TestFetchCrtDataExhaustsRetries(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()

	origCrt, origCS, origBackoff := CrtBaseURL, CertSpotterBaseURL, initialBackoff
	CrtBaseURL = down.URL
	CertSpotterBaseURL = down.URL
	initialBackoff = time.Millisecond
	defer func() { CrtBaseURL, CertSpotterBaseURL, initialBackoff = origCrt, origCS, origBackoff }()

	if _, err := FetchCrtData("example.com"); err == nil {
		t.Fatal("expected error after exhausting retries, got nil")
	}
}

// TestFetchCrtDataFallsBackToCertSpotter verifies that when crt.sh is down, the
// certspotter fallback is used and its response is mapped to the template shape.
func TestFetchCrtDataFallsBackToCertSpotter(t *testing.T) {
	crtDown := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer crtDown.Close()

	certSpotter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"123","dns_names":["example.com","www.example.com"],"issuer":{"name":"CN=Test CA"}}]`))
	}))
	defer certSpotter.Close()

	origCrt, origCS, origBackoff := CrtBaseURL, CertSpotterBaseURL, initialBackoff
	CrtBaseURL = crtDown.URL
	CertSpotterBaseURL = certSpotter.URL
	initialBackoff = time.Millisecond
	defer func() { CrtBaseURL, CertSpotterBaseURL, initialBackoff = origCrt, origCS, origBackoff }()

	data, err := FetchCrtData("example.com")
	if err != nil {
		t.Fatalf("expected certspotter fallback to succeed, got %v", err)
	}
	if len(data) != 1 {
		t.Fatalf("expected 1 record, got %d", len(data))
	}
	rec := data[0]
	if rec["common_name"] != "example.com" {
		t.Errorf("common_name = %v, want example.com", rec["common_name"])
	}
	if rec["issuer_name"] != "CN=Test CA" {
		t.Errorf("issuer_name = %v, want CN=Test CA", rec["issuer_name"])
	}
	if id, ok := rec["id"].(float64); !ok || id != 123 {
		t.Errorf("id = %v (%T), want float64 123", rec["id"], rec["id"])
	}
}

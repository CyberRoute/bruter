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

// TestFetchCrtDataExhaustsRetries verifies a persistent 503 fails with a clear error.
func TestFetchCrtDataExhaustsRetries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	origURL, origBackoff := CrtBaseURL, initialBackoff
	CrtBaseURL = server.URL
	initialBackoff = time.Millisecond
	defer func() { CrtBaseURL, initialBackoff = origURL, origBackoff }()

	if _, err := FetchCrtData("example.com"); err == nil {
		t.Fatal("expected error after exhausting retries, got nil")
	}
}

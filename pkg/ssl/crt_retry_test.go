package ssl

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestFetchCertSpotterRetriesTransient verifies that when crt.sh is down, a
// transient 504 from the certspotter fallback is retried and a subsequent 200
// succeeds, rather than failing the whole lookup on one bad gateway response.
func TestFetchCertSpotterRetriesTransient(t *testing.T) {
	crtDown := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer crtDown.Close()

	var calls int32
	certSpotter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			// First two attempts: simulate a certspotter gateway timeout.
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"123","dns_names":["example.com"],"issuer":{"name":"CN=Test CA"}}]`))
	}))
	defer certSpotter.Close()

	origCrt, origCS, origBackoff := CrtBaseURL, CertSpotterBaseURL, initialBackoff
	CrtBaseURL = crtDown.URL
	CertSpotterBaseURL = certSpotter.URL
	initialBackoff = time.Millisecond
	defer func() { CrtBaseURL, CertSpotterBaseURL, initialBackoff = origCrt, origCS, origBackoff }()

	data, err := FetchCrtData("example.com")
	if err != nil {
		t.Fatalf("expected certspotter retry to succeed, got %v", err)
	}
	if len(data) != 1 {
		t.Fatalf("expected 1 record, got %d", len(data))
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("expected 3 certspotter attempts (2 x 504 + 1 x 200), got %d", got)
	}
}

// TestFetchCrtDataExhaustsRetries verifies that when both crt.sh (persistent
// 503) and the certspotter fallback fail, a clear combined error is returned.
func TestFetchCrtDataExhaustsRetries(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()

	restore := allSourcesTo(down.URL)
	defer restore()
	origDialer := liveCertDialer
	initialBackoff = time.Millisecond
	// Make the live-TLS fallback fail too, so the lookup truly exhausts.
	liveCertDialer = func(context.Context, string, *tls.Config) (*tls.Conn, error) {
		return nil, errLiveDialTest
	}
	defer func() { liveCertDialer = origDialer }()

	if _, err := FetchCrtData("example.com"); err == nil {
		t.Fatal("expected error after exhausting retries, got nil")
	}
}

// allSourcesTo points every HTTP aggregator base URL at url (used to simulate a
// total aggregator outage) and returns a function that restores them and the
// backoff. The caller still controls liveCertDialer separately.
func allSourcesTo(url string) func() {
	origCrt, origCS, origShodan, origCrtName, origBackoff :=
		CrtBaseURL, CertSpotterBaseURL, ShodanCTLBaseURL, CrtNameBaseURL, initialBackoff
	CrtBaseURL, CertSpotterBaseURL, ShodanCTLBaseURL, CrtNameBaseURL = url, url, url, url
	return func() {
		CrtBaseURL, CertSpotterBaseURL, ShodanCTLBaseURL, CrtNameBaseURL, initialBackoff =
			origCrt, origCS, origShodan, origCrtName, origBackoff
	}
}

var errLiveDialTest = errors.New("dial disabled in test")

// TestFetchCrtDataRespectsOverallTimeout verifies that a source which never
// responds cannot hang the lookup past the overall deadline.
func TestFetchCrtDataRespectsOverallTimeout(t *testing.T) {
	// A server that blocks until the client's context is cancelled.
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer hang.Close()

	restore := allSourcesTo(hang.URL)
	defer restore()
	origDialer, origTimeout := liveCertDialer, overallTimeout
	overallTimeout = 200 * time.Millisecond
	initialBackoff = time.Millisecond
	// Live dialer also blocks until the overall context is cancelled.
	liveCertDialer = func(ctx context.Context, _ string, _ *tls.Config) (*tls.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	defer func() { liveCertDialer, overallTimeout = origDialer, origTimeout }()

	start := time.Now()
	if _, err := FetchCrtData("example.com"); err == nil {
		t.Fatal("expected error when all sources hang, got nil")
	}
	// Generous upper bound: the deadline is 200ms; anything near the per-request
	// 15s client timeout would mean the overall deadline was not honoured.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("lookup took %s; overall timeout was not honoured", elapsed)
	}
}

// TestFetchLiveCertFallback verifies that when both CT aggregators are down,
// the live certificate served by the target over TLS is read and mapped into
// the template shape.
func TestFetchLiveCertFallback(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()

	// A TLS server whose cert carries DNS SANs we can assert on.
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer tlsSrv.Close()
	srvAddr := strings.TrimPrefix(tlsSrv.URL, "https://")

	restore := allSourcesTo(down.URL)
	defer restore()
	origDialer := liveCertDialer
	initialBackoff = time.Millisecond
	// Redirect the dial to the test server and trust its self-signed cert.
	liveCertDialer = func(_ context.Context, _ string, cfg *tls.Config) (*tls.Conn, error) {
		cfg.RootCAs = tlsSrv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
		return tls.Dial("tcp", srvAddr, cfg)
	}
	defer func() { liveCertDialer = origDialer }()

	// httptest's TLS cert is issued for 127.0.0.1 / example.com; use that as SNI.
	data, err := FetchCrtData("example.com")
	if err != nil {
		t.Fatalf("expected live-cert fallback to succeed, got %v", err)
	}
	if len(data) != 1 {
		t.Fatalf("expected 1 record, got %d", len(data))
	}
	if data[0]["issuer_name"] == "" {
		t.Errorf("expected a non-empty issuer_name from the live cert")
	}
}

// TestFetchShodanCTLFallback verifies that when crt.sh and certspotter are
// down, the Shodan CTL hostname feed is used and mapped into the template shape.
func TestFetchShodanCTLFallback(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer down.Close()

	shodan := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`["example.com","www.example.com","*.example.com"]`))
	}))
	defer shodan.Close()

	restore := allSourcesTo(down.URL)
	defer restore()
	ShodanCTLBaseURL = shodan.URL
	initialBackoff = time.Millisecond

	data, err := FetchCrtData("example.com")
	if err != nil {
		t.Fatalf("expected shodan-ctl fallback to succeed, got %v", err)
	}
	if len(data) != 1 {
		t.Fatalf("expected 1 record, got %d", len(data))
	}
	// Three names, one a wildcard dupe of example.com → two unique identities.
	nv, _ := data[0]["name_value"].(string)
	if nv != "example.com\nwww.example.com" {
		t.Errorf("name_value = %q, want the two deduped hostnames", nv)
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

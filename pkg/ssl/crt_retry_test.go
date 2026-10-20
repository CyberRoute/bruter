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

var errLiveDialTest = errors.New("dial disabled in test")

// allSourcesTo points every HTTP source base URL at url (used to simulate a
// total outage, or to park non-target sources on a failing server) and returns
// a function that restores them and the backoff. The live-TLS dialer is handled
// separately by the caller.
func allSourcesTo(url string) func() {
	origCrt, origCS, origShodan, origCrtName := CrtBaseURL, CertSpotterBaseURL, ShodanCTLBaseURL, CrtNameBaseURL
	origOTX, origHT, origURLScan := OTXBaseURL, HackerTargetBaseURL, URLScanBaseURL
	origBackoff := initialBackoff
	CrtBaseURL, CertSpotterBaseURL, ShodanCTLBaseURL, CrtNameBaseURL = url, url, url, url
	OTXBaseURL, HackerTargetBaseURL, URLScanBaseURL = url, url, url
	return func() {
		CrtBaseURL, CertSpotterBaseURL, ShodanCTLBaseURL, CrtNameBaseURL = origCrt, origCS, origShodan, origCrtName
		OTXBaseURL, HackerTargetBaseURL, URLScanBaseURL = origOTX, origHT, origURLScan
		initialBackoff = origBackoff
	}
}

// isolateSources parks every HTTP source on a persistent-503 server and disables
// the live-TLS dialer, so a test can then enable exactly the source(s) it
// exercises by overriding their base URL (or the dialer) afterwards. Because
// FetchCrtData now queries all sources concurrently and merges the results,
// non-target sources must be neutralised or they would hit the real network and
// pollute the merged output. It shrinks the retry backoff and returns a restore
// function (which also closes the 503 server).
func isolateSources() func() {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	restoreURLs := allSourcesTo(down.URL)
	initialBackoff = time.Millisecond
	origDialer := liveCertDialer
	liveCertDialer = func(context.Context, string, *tls.Config) (*tls.Conn, error) {
		return nil, errLiveDialTest
	}
	return func() {
		liveCertDialer = origDialer
		restoreURLs()
		down.Close()
	}
}

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

	defer isolateSources()()
	CrtBaseURL = server.URL // enable only crt.sh

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

// TestFetchCertSpotterRetriesTransient verifies that a transient 504 from the
// certspotter source is retried and a subsequent 200 succeeds.
func TestFetchCertSpotterRetriesTransient(t *testing.T) {
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

	defer isolateSources()()
	CertSpotterBaseURL = certSpotter.URL // enable only certspotter

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

// TestFetchCrtDataExhaustsRetries verifies that when every source fails, a clear
// combined error is returned.
func TestFetchCrtDataExhaustsRetries(t *testing.T) {
	defer isolateSources()() // all HTTP sources 503, live dialer disabled

	if _, err := FetchCrtData("example.com"); err == nil {
		t.Fatal("expected error after exhausting retries, got nil")
	}
}

// TestFetchCrtDataRespectsOverallTimeout verifies that sources which never
// respond cannot hang the lookup past the overall deadline.
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

// TestFetchLiveCertFallback verifies that when every aggregator is down, the
// live certificate served by the target over TLS is read and merged in.
func TestFetchLiveCertFallback(t *testing.T) {
	// A TLS server whose cert carries DNS SANs we can assert on.
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer tlsSrv.Close()
	srvAddr := strings.TrimPrefix(tlsSrv.URL, "https://")

	defer isolateSources()() // all aggregators down...
	// ...but enable the live-TLS dialer, pointed at the test server.
	liveCertDialer = func(_ context.Context, _ string, cfg *tls.Config) (*tls.Conn, error) {
		cfg.RootCAs = tlsSrv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
		return tls.Dial("tcp", srvAddr, cfg)
	}

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

// TestFetchShodanCTLFallback verifies that the Shodan CTL hostname feed is used
// and mapped into the expected shape.
func TestFetchShodanCTLFallback(t *testing.T) {
	shodan := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`["example.com","www.example.com","*.example.com"]`))
	}))
	defer shodan.Close()

	defer isolateSources()()
	ShodanCTLBaseURL = shodan.URL // enable only shodan-ctl

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
// certspotter source is used and its response is mapped to the expected shape.
func TestFetchCrtDataFallsBackToCertSpotter(t *testing.T) {
	certSpotter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"123","dns_names":["example.com","www.example.com"],"issuer":{"name":"CN=Test CA"}}]`))
	}))
	defer certSpotter.Close()

	defer isolateSources()()
	CertSpotterBaseURL = certSpotter.URL // enable only certspotter

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

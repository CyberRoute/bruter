package ssl

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// CrtBaseURL is the crt.sh endpoint. It is a variable so tests can point it at
// a mock server.
var CrtBaseURL = "https://crt.sh"

// CertSpotterBaseURL is the certspotter endpoint used as a fallback when crt.sh
// is unavailable. It is a variable so tests can point it at a mock server.
var CertSpotterBaseURL = "https://api.certspotter.com"

// ShodanCTLBaseURL is Shodan's free certificate-transparency hostname feed,
// used as a further no-auth fallback. It is a variable so tests can override it.
var ShodanCTLBaseURL = "https://ctl.shodan.io"

// CrtNameBaseURL is the crt.name endpoint, a further no-auth fallback that
// returns a plaintext hostname list. It is a variable so tests can override it.
var CrtNameBaseURL = "https://crt.name"

// userAgent is sent on certificate-transparency requests. crt.sh aggressively
// rate-limits the default Go User-Agent, so we identify ourselves explicitly.
const userAgent = "bruter/1.0 (+https://github.com/CyberRoute/bruter)"

// maxRetries is how many times a transient crt.sh failure (429 / 5xx) is retried.
const maxRetries = 4

// initialBackoff is the first retry delay; it doubles each attempt. It is a
// variable so tests can shrink it.
var initialBackoff = time.Second

// overallTimeout caps the whole multi-source lookup so that stacked retries and
// timeouts across every source can never hang the caller for minutes. It is a
// variable so tests can shrink it.
var overallTimeout = 45 * time.Second

// perSourceTimeout caps how long any single source (including its retries) may
// run. Because sources are queried concurrently (see FetchCrtData), one slow or
// rate-limited source cannot delay the others — this just bounds the straggler.
// Variable for tests.
var perSourceTimeout = 15 * time.Second

// OTXBaseURL is AlienVault OTX's passive-DNS endpoint, a free no-auth source.
// Variable so tests can point it at a mock server.
var OTXBaseURL = "https://otx.alienvault.com"

// HackerTargetBaseURL is HackerTarget's hostsearch endpoint (free, returns CSV).
// Variable so tests can point it at a mock server.
var HackerTargetBaseURL = "https://api.hackertarget.com"

// URLScanBaseURL is urlscan.io's search endpoint, a free passive source whose
// results carry observed hostnames. Variable so tests can override it.
var URLScanBaseURL = "https://urlscan.io"

// parseRetryAfter interprets a Retry-After header, which may be a number of
// seconds or an HTTP-date. It returns 0 if absent or unparseable.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := time.ParseDuration(v + "s"); err == nil {
		return secs
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// FetchCrtData returns certificate-transparency records for the domain by
// trying several independent sources in order, returning the first that
// succeeds. The two rich sources (crt.sh, certspotter) come first; two further
// no-auth aggregators (Shodan CTL, crt.name) back them up when both are
// overloaded — they share less failure-mode overlap than two crt.sh-style
// services alone. The final fallback reads the certificate the target itself
// serves over TLS, which depends on no third party at all. The last three
// sources yield hostnames/served SANs rather than full CT history, but
// returning real data beats returning nothing during an aggregator outage.
func FetchCrtData(domain string) ([]map[string]interface{}, error) {
	overallDeadline := time.Now().Add(overallTimeout)

	type source struct {
		name  string
		fetch func(context.Context, string) ([]map[string]interface{}, error)
	}
	// Independent passive sources. They are queried concurrently and their
	// results merged, so reliability comes from redundancy: a single source
	// being down or rate-limited no longer fails (or even delays) the lookup,
	// and several answering yields a richer union. The mix deliberately spans
	// different failure modes — CT logs (crt.sh, certspotter), passive DNS
	// (OTX, HackerTarget, urlscan), hostname feeds (Shodan CTL, crt.name) — plus
	// a no-third-party floor that reads the certificate the target itself serves.
	sources := []source{
		{"crt.sh", fetchCrtSh},
		{"certspotter", fetchCertSpotter},
		{"otx", fetchOTX},
		{"hackertarget", fetchHackerTarget},
		{"urlscan", fetchURLScan},
		{"shodan-ctl", fetchShodanCTL},
		{"crt.name", fetchCrtName},
		{"live TLS", fetchLiveCert},
	}

	type result struct {
		name string
		recs []map[string]interface{}
		err  error
	}
	ch := make(chan result, len(sources))
	for _, s := range sources {
		s := s
		go func() {
			// Bound each source by its own cap and the overall deadline.
			budget := time.Until(overallDeadline)
			if budget > perSourceTimeout {
				budget = perSourceTimeout
			}
			if budget <= 0 {
				ch <- result{s.name, nil, fmt.Errorf("skipped (deadline reached)")}
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			recs, err := s.fetch(ctx, domain)
			ch <- result{s.name, recs, err}
		}()
	}

	var all []map[string]interface{}
	var errs []string
	for i := 0; i < len(sources); i++ {
		r := <-ch
		if r.err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", r.name, r.err))
			continue
		}
		all = append(all, r.recs...)
	}

	// Only a total outage — every source failing — is an error. Any single
	// source answering is enough to return data (deduped downstream by the UI).
	if len(all) == 0 {
		return nil, fmt.Errorf("certificate lookup failed (%s)", strings.Join(errs, "; "))
	}
	return all, nil
}

// namesToRecords maps a bare list of hostnames (from sources that return names
// only, with no issuer or CT-log id) into one record in the shape the SSL
// template expects. Names are normalised and deduplicated; issuer_name records
// which source they came from so the user knows this is reduced fallback data.
// It errors when no usable names are found so the caller falls through to the
// next source rather than returning an empty page.
func namesToRecords(names []string, source string) ([]map[string]interface{}, error) {
	seen := make(map[string]bool)
	unique := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		n = strings.TrimPrefix(n, "*.")
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		unique = append(unique, n)
	}
	if len(unique) == 0 {
		return nil, fmt.Errorf("%s returned no hostnames", source)
	}

	commonName := unique[0]
	return []map[string]interface{}{{
		// These sources expose no CT-log id; the template renders 0.
		"id":          float64(0),
		"common_name": commonName,
		"name_value":  strings.Join(unique, "\n"),
		"issuer_name": fmt.Sprintf("(hostnames from %s — issuer not available)", source),
	}}, nil
}

// fetchShodanCTL queries Shodan's free certificate-transparency hostname feed,
// which returns a JSON array of hostnames and needs no API key.
func fetchShodanCTL(ctx context.Context, domain string) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/v1/domain/%s/hostnames", ShodanCTLBaseURL, domain)

	response, err := getWithRetry(ctx, "shodan-ctl", url, true)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var names []string
	if err := json.NewDecoder(response.Body).Decode(&names); err != nil {
		return nil, fmt.Errorf("shodan-ctl response decode failed: %w", err)
	}
	return namesToRecords(names, "Shodan CTL")
}

// fetchCrtName queries crt.name, which returns a newline-separated plaintext
// list of hostnames and needs no API key.
func fetchCrtName(ctx context.Context, domain string) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/v1/search?apex=%s", CrtNameBaseURL, domain)

	response, err := getWithRetry(ctx, "crt.name", url, false)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var names []string
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		names = append(names, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("crt.name response read failed: %w", err)
	}
	return namesToRecords(names, "crt.name")
}

// liveCertDialer connects for the live-certificate fallback. It is a variable
// so tests can point it at a local TLS server. The context bounds the dial so
// it cannot outlive the overall lookup deadline.
var liveCertDialer = func(ctx context.Context, address string, cfg *tls.Config) (*tls.Conn, error) {
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	return conn.(*tls.Conn), nil
}

// fetchLiveCert connects to the target over TLS and reads the leaf certificate
// it serves, mapping it into the same shape the SSL template expects. This is
// the last-resort fallback used when every CT aggregator is unavailable.
func fetchLiveCert(ctx context.Context, domain string) ([]map[string]interface{}, error) {
	address := net.JoinHostPort(domain, "443")
	conn, err := liveCertDialer(ctx, address, &tls.Config{ServerName: domain})
	if err != nil {
		return nil, fmt.Errorf("live TLS dial failed: %w", err)
	}
	defer conn.Close()

	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, fmt.Errorf("live TLS: server presented no certificate")
	}
	leaf := chain[0]

	commonName := leaf.Subject.CommonName
	if commonName == "" && len(leaf.DNSNames) > 0 {
		commonName = leaf.DNSNames[0]
	}

	return []map[string]interface{}{{
		// No CT-log id exists for a live-read cert; the template renders 0.
		"id":          float64(0),
		"common_name": commonName,
		"name_value":  strings.Join(leaf.DNSNames, "\n"),
		"issuer_name": leaf.Issuer.String(),
	}}, nil
}

// getWithRetry performs a GET, retrying transient failures: network errors,
// 429 (rate limit) and 5xx. When expectJSON is set it also retries HTML error
// pages that slip through with a non-JSON content type (crt.sh does this when
// overloaded). service names the endpoint for error messages. The caller owns
// closing the returned (200) response body.
func getWithRetry(ctx context.Context, service, url string, expectJSON bool) (*http.Response, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	backoff := initialBackoff

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("%s request build failed: %w", service, err)
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "application/json")

		response, err := client.Do(req)
		if err != nil {
			// A cancelled/expired overall deadline is terminal: stop retrying.
			if ctx.Err() != nil {
				return nil, fmt.Errorf("%s aborted: %w", service, ctx.Err())
			}
			lastErr = fmt.Errorf("%s request failed: %w", service, err)
			if !sleepBackoff(ctx, &backoff, attempt) {
				break
			}
			continue
		}

		// These CT services are overloaded often; 429 and 5xx are transient.
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
			lastErr = fmt.Errorf("%s unavailable: HTTP %d", service, response.StatusCode)
			retryAfter := parseRetryAfter(response.Header.Get("Retry-After"))
			_ = response.Body.Close()
			if attempt < maxRetries {
				if retryAfter == 0 {
					retryAfter = backoff
				}
				if !sleepCtx(ctx, retryAfter) {
					break
				}
				backoff *= 2
			}
			continue
		}

		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			return nil, fmt.Errorf("%s unavailable: HTTP %d", service, response.StatusCode)
		}

		// A non-JSON body means an HTML error page slipped through; treat as transient.
		if expectJSON {
			if ct := response.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
				_ = response.Body.Close()
				lastErr = fmt.Errorf("%s returned a non-JSON response (service may be down)", service)
				if !sleepBackoff(ctx, &backoff, attempt) {
					break
				}
				continue
			}
		}

		return response, nil
	}

	return nil, fmt.Errorf("%s failed after %d attempts: %w", service, maxRetries, lastErr)
}

// fetchCrtSh queries crt.sh, retrying transient 429/5xx responses. The query
// uses a "%.domain" wildcard so subdomain certificates are included, matching
// the identity form crt.sh expects (%25 is a percent-encoded '%').
func fetchCrtSh(ctx context.Context, domain string) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/?q=%%25.%s&output=json", CrtBaseURL, domain)

	response, err := getWithRetry(ctx, "crt.sh", url, true)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var data []map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("crt.sh response decode failed: %w", err)
	}
	return data, nil
}

// certSpotterIssuance is the subset of the certspotter API response we use.
type certSpotterIssuance struct {
	ID       string   `json:"id"`
	DNSNames []string `json:"dns_names"`
	Issuer   struct {
		Name string `json:"name"`
	} `json:"issuer"`
}

// fetchCertSpotter queries certspotter and maps its response into the same
// shape the SSL template expects (id, common_name, name_value, issuer_name).
func fetchCertSpotter(ctx context.Context, domain string) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names&expand=issuer",
		CertSpotterBaseURL, domain)

	response, err := getWithRetry(ctx, "certspotter", url, true)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var issuances []certSpotterIssuance
	if err := json.NewDecoder(response.Body).Decode(&issuances); err != nil {
		return nil, fmt.Errorf("certspotter response decode failed: %w", err)
	}

	data := make([]map[string]interface{}, 0, len(issuances))
	for _, iss := range issuances {
		var commonName string
		if len(iss.DNSNames) > 0 {
			commonName = iss.DNSNames[0]
		}
		// The template renders id with %0.0f, so coerce the string id to a number.
		var id float64
		if n, convErr := strconv.ParseFloat(iss.ID, 64); convErr == nil {
			id = n
		}
		data = append(data, map[string]interface{}{
			"id":          id,
			"common_name": commonName,
			"name_value":  strings.Join(iss.DNSNames, "\n"),
			"issuer_name": iss.Issuer.Name,
		})
	}
	return data, nil
}

// otxPassiveDNS is the subset of the AlienVault OTX passive-DNS response we use.
type otxPassiveDNS struct {
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
}

// fetchOTX queries AlienVault OTX's passive-DNS feed, a free no-auth source that
// returns hostnames historically observed resolving under the domain.
func fetchOTX(ctx context.Context, domain string) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/v1/indicators/domain/%s/passive_dns", OTXBaseURL, domain)

	response, err := getWithRetry(ctx, "otx", url, true)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var payload otxPassiveDNS
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("otx response decode failed: %w", err)
	}
	names := make([]string, 0, len(payload.PassiveDNS))
	for _, e := range payload.PassiveDNS {
		names = append(names, e.Hostname)
	}
	return namesToRecords(names, "AlienVault OTX")
}

// fetchHackerTarget queries HackerTarget's hostsearch endpoint, which returns a
// free-tier CSV of "hostname,ip" lines. When the daily quota is exceeded it
// returns a plaintext error instead, which yields no valid hostnames and is
// surfaced as a failed source.
func fetchHackerTarget(ctx context.Context, domain string) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/hostsearch/?q=%s", HackerTargetBaseURL, domain)

	response, err := getWithRetry(ctx, "hackertarget", url, false)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var names []string
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		host, _, ok := strings.Cut(line, ",")
		// Only "host,ip" rows are real results; error prose ("API count
		// exceeded …") has no comma or embedded spaces and is skipped.
		if !ok || strings.ContainsAny(host, " \t") || !strings.Contains(host, ".") {
			continue
		}
		names = append(names, host)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("hackertarget response read failed: %w", err)
	}
	return namesToRecords(names, "HackerTarget")
}

// urlScanSearch is the subset of the urlscan.io search response we use.
type urlScanSearch struct {
	Results []struct {
		Page struct {
			Domain string `json:"domain"`
		} `json:"page"`
		Task struct {
			Domain string `json:"domain"`
		} `json:"task"`
	} `json:"results"`
}

// fetchURLScan queries urlscan.io's free search API, whose indexed scans carry
// observed hostnames for the domain (page/task domains).
func fetchURLScan(ctx context.Context, domain string) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/api/v1/search/?q=domain:%s&size=10000", URLScanBaseURL, domain)

	response, err := getWithRetry(ctx, "urlscan", url, true)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var payload urlScanSearch
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("urlscan response decode failed: %w", err)
	}
	names := make([]string, 0, len(payload.Results)*2)
	for _, r := range payload.Results {
		names = append(names, r.Page.Domain, r.Task.Domain)
	}
	return namesToRecords(names, "urlscan.io")
}

// sleepBackoff waits for the current backoff and doubles it, unless this was
// the final attempt. It returns false if the context was cancelled during the
// wait (or this was the final attempt), signalling the caller to stop.
func sleepBackoff(ctx context.Context, backoff *time.Duration, attempt int) bool {
	if attempt >= maxRetries {
		return false
	}
	if !sleepCtx(ctx, *backoff) {
		return false
	}
	*backoff *= 2
	return true
}

// sleepCtx waits for d or until ctx is cancelled, whichever comes first. It
// returns false if the context was cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

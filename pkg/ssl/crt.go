package ssl

import (
	"encoding/json"
	"fmt"
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

// userAgent is sent on certificate-transparency requests. crt.sh aggressively
// rate-limits the default Go User-Agent, so we identify ourselves explicitly.
const userAgent = "bruter/1.0 (+https://github.com/CyberRoute/bruter)"

// maxRetries is how many times a transient crt.sh failure (429 / 5xx) is retried.
const maxRetries = 4

// initialBackoff is the first retry delay; it doubles each attempt. It is a
// variable so tests can shrink it.
var initialBackoff = time.Second

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

// FetchCrtData returns certificate-transparency records for the domain. It
// queries crt.sh first and, if that service is unavailable, falls back to
// certspotter so results are still returned during crt.sh outages.
func FetchCrtData(domain string) ([]map[string]interface{}, error) {
	data, crtErr := fetchCrtSh(domain)
	if crtErr == nil {
		return data, nil
	}

	data, csErr := fetchCertSpotter(domain)
	if csErr == nil {
		return data, nil
	}

	return nil, fmt.Errorf("certificate lookup failed (crt.sh: %v; certspotter: %v)", crtErr, csErr)
}

// fetchCrtSh queries crt.sh, retrying transient 429/5xx responses.
func fetchCrtSh(domain string) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/?q=%s&output=json", CrtBaseURL, domain)

	client := &http.Client{Timeout: 15 * time.Second}
	backoff := initialBackoff

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("crt.sh request build failed: %w", err)
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "application/json")

		response, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("crt.sh request failed: %w", err)
			sleepBackoff(&backoff, attempt)
			continue
		}

		// crt.sh is overloaded often; 429 (rate limit) and 5xx are transient.
		if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
			lastErr = fmt.Errorf("crt.sh unavailable: HTTP %d", response.StatusCode)
			retryAfter := parseRetryAfter(response.Header.Get("Retry-After"))
			_ = response.Body.Close()
			if attempt < maxRetries {
				if retryAfter == 0 {
					retryAfter = backoff
				}
				time.Sleep(retryAfter)
				backoff *= 2
			}
			continue
		}

		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			return nil, fmt.Errorf("crt.sh unavailable: HTTP %d", response.StatusCode)
		}

		// A non-JSON body means an HTML error page slipped through; treat as transient.
		if ct := response.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
			_ = response.Body.Close()
			lastErr = fmt.Errorf("crt.sh returned a non-JSON response (service may be down)")
			sleepBackoff(&backoff, attempt)
			continue
		}

		var data []map[string]interface{}
		err = json.NewDecoder(response.Body).Decode(&data)
		_ = response.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("crt.sh response decode failed: %w", err)
		}
		return data, nil
	}

	return nil, fmt.Errorf("crt.sh failed after %d attempts: %w", maxRetries, lastErr)
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
func fetchCertSpotter(domain string) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names&expand=issuer",
		CertSpotterBaseURL, domain)

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("certspotter request build failed: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certspotter request failed: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certspotter unavailable: HTTP %d", response.StatusCode)
	}

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

// sleepBackoff waits for the current backoff and doubles it, unless this was
// the final attempt.
func sleepBackoff(backoff *time.Duration, attempt int) {
	if attempt < maxRetries {
		time.Sleep(*backoff)
		*backoff *= 2
	}
}

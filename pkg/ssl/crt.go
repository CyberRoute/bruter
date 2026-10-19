package ssl

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CrtBaseURL is the crt.sh endpoint. It is a variable so tests can point it at
// a mock server.
var CrtBaseURL = "https://crt.sh"

// userAgent is sent on crt.sh requests. crt.sh aggressively rate-limits the
// default Go User-Agent, so we identify ourselves explicitly.
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

func FetchCrtData(domain string) ([]map[string]interface{}, error) {
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

// sleepBackoff waits for the current backoff and doubles it, unless this was
// the final attempt.
func sleepBackoff(backoff *time.Duration, attempt int) {
	if attempt < maxRetries {
		time.Sleep(*backoff)
		*backoff *= 2
	}
}

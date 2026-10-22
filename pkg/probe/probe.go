// Package probe performs lightweight HTTP probing of discovered hosts: it
// resolves each name, fetches the root over HTTPS (falling back to HTTP),
// and extracts the signals a hunter triages on — status, title, server,
// technology hints, CORS reflection, missing security headers — and runs a
// subdomain-takeover check using the host's CNAME and response body.
package probe

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// maxBodyRead bounds how much of each response body is read: enough to capture
// a <title> and a takeover fingerprint, without buffering large pages.
const maxBodyRead = 64 * 1024

// defaultWorkers is the fan-out for probing many hosts (HTTP is I/O-bound).
const defaultWorkers = 20

// corsProbeOrigin is the attacker-style Origin sent to detect reflective CORS.
const corsProbeOrigin = "https://bruter-cors-probe.example.com"

// securityHeaders is the set whose absence is reported as a weakness.
var securityHeaders = []string{
	"Content-Security-Policy",
	"Strict-Transport-Security",
	"X-Frame-Options",
	"X-Content-Type-Options",
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// Result is the outcome of probing one host.
type Result struct {
	Host           string    `json:"host"`
	URL            string    `json:"url"`
	IP             string    `json:"ip"`
	Status         int       `json:"status"`
	Title          string    `json:"title"`
	Server         string    `json:"server"`
	PoweredBy      string    `json:"powered_by"`
	ContentLength  int64     `json:"content_length"`
	RedirectTo     string    `json:"redirect_to"`
	Tech           []string  `json:"tech"`
	CORS           string    `json:"cors"`
	MissingHeaders []string  `json:"missing_headers"`
	Takeover       *Takeover `json:"takeover,omitempty"`
	Error          string    `json:"error,omitempty"`
}

// client is shared across probes: connections pooled, certs not verified
// (probing untrusted hosts), redirects captured rather than followed so the
// first response's status and Location are reported as-is.
var client = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // probing untrusted hosts by design
		MaxIdleConnsPerHost: 4,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// cnameLookup is the resolver used for takeover CNAME checks; a var so tests
// can stub it.
var cnameLookup = net.LookupCNAME

// ProbeHosts probes every host concurrently and returns the results sorted by
// host name. workers <= 0 uses a default. The supplied ctx bounds the run.
func ProbeHosts(ctx context.Context, hosts []string, workers int) []Result {
	if workers <= 0 {
		workers = defaultWorkers
	}
	// De-duplicate and normalise input.
	seen := make(map[string]struct{})
	clean := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		h = strings.TrimPrefix(h, "*.")
		if h == "" || !strings.Contains(h, ".") {
			continue
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		clean = append(clean, h)
	}

	results := make([]Result, 0, len(clean))
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan string)

	worker := func() {
		defer wg.Done()
		for h := range jobs {
			r := probeOne(ctx, h)
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}
	}

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}

feed:
	for _, h := range clean {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- h:
		}
	}
	close(jobs)
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Host < results[j].Host })
	return results
}

func probeOne(ctx context.Context, host string) Result {
	res := Result{Host: host, Tech: []string{}, MissingHeaders: []string{}}

	if ips, err := net.LookupHost(host); err == nil && len(ips) > 0 {
		res.IP = ips[0]
	}

	// Takeover detection needs the CNAME regardless of whether HTTP responds.
	cname, _ := cnameLookup(host)

	var body string
	var responded bool
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + host + "/"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "bruter/1.0 (+https://github.com/CyberRoute/bruter)")
		req.Header.Set("Origin", corsProbeOrigin)

		resp, err := client.Do(req)
		if err != nil {
			res.Error = err.Error()
			continue
		}
		responded = true
		res.Error = ""
		res.URL = url
		res.Status = resp.StatusCode
		res.Server = resp.Header.Get("Server")
		res.PoweredBy = resp.Header.Get("X-Powered-By")
		res.ContentLength = resp.ContentLength
		if loc := resp.Header.Get("Location"); loc != "" {
			res.RedirectTo = loc
		}
		res.CORS = classifyCORS(resp.Header)
		res.MissingHeaders = missingSecurityHeaders(resp.Header)

		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
		_ = resp.Body.Close()
		body = string(b)
		res.Title = extractTitle(body)
		res.Tech = detectTech(resp.Header, body)
		break
	}

	// Run the takeover check with whatever body we have (empty if the host did
	// not respond — some takeover signatures are CNAME-only).
	if cname != "" {
		if t := checkTakeover(cname, body); t != nil {
			res.Takeover = t
		}
	}

	if !responded && res.Error == "" {
		res.Error = "no HTTP response"
	}
	return res
}

func extractTitle(body string) string {
	m := titleRe.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	title := strings.TrimSpace(m[1])
	title = strings.Join(strings.Fields(title), " ") // collapse whitespace
	if len(title) > 200 {
		title = title[:200]
	}
	return title
}

// classifyCORS inspects the response to the attacker-origin probe. A server
// that reflects the probe origin (especially with credentials) or returns a
// wildcard is flagged; anything else is "".
func classifyCORS(h http.Header) string {
	acao := h.Get("Access-Control-Allow-Origin")
	acac := strings.EqualFold(h.Get("Access-Control-Allow-Credentials"), "true")
	switch {
	case acao == corsProbeOrigin && acac:
		return "reflects arbitrary origin with credentials"
	case acao == corsProbeOrigin:
		return "reflects arbitrary origin"
	case acao == "*" && acac:
		return "wildcard with credentials"
	case acao == "*":
		return "wildcard"
	default:
		return ""
	}
}

func missingSecurityHeaders(h http.Header) []string {
	missing := make([]string, 0, len(securityHeaders))
	for _, name := range securityHeaders {
		if h.Get(name) == "" {
			missing = append(missing, name)
		}
	}
	return missing
}

// detectTech applies a small set of header/body signatures. It is intentionally
// lightweight — a hint for triage, not a full fingerprinting engine.
func detectTech(h http.Header, body string) []string {
	tech := []string{}
	add := func(name string) {
		for _, t := range tech {
			if t == name {
				return
			}
		}
		tech = append(tech, name)
	}

	if v := h.Get("Server"); v != "" {
		add(v)
	}
	if v := h.Get("X-Powered-By"); v != "" {
		add(v)
	}
	if h.Get("X-AspNet-Version") != "" {
		add("ASP.NET")
	}
	if h.Get("X-Drupal-Cache") != "" {
		add("Drupal")
	}
	lb := strings.ToLower(body)
	for marker, name := range map[string]string{
		"wp-content":           "WordPress",
		"/sites/default/files": "Drupal",
		"joomla":               "Joomla",
		"__next_data__":        "Next.js",
		"ng-version":           "Angular",
		"data-reactroot":       "React",
		"csrf-param":           "Ruby on Rails",
		"x-shopify":            "Shopify",
	} {
		if strings.Contains(lb, marker) {
			add(name)
		}
	}
	sort.Strings(tech)
	return tech
}

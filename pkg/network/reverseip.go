package network

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ReverseIPBaseURL is HackerTarget's reverse-IP endpoint, a free no-auth source
// that maps an IP address to the host names pointing at it. It is a variable so
// tests can point it at a mock server.
var ReverseIPBaseURL = "https://api.hackertarget.com"

// reverseIPUserAgent identifies our requests; HackerTarget (like crt.sh) treats
// the default Go User-Agent more harshly.
const reverseIPUserAgent = "bruter/1.0 (+https://github.com/CyberRoute/bruter)"

// ReverseIPResult is the set of host names observed on a shared IP. Hosts other
// than the scanned domain are "neighbours" — other sites on the same server,
// useful for expanding scope on dedicated hosting.
type ReverseIPResult struct {
	IP    string   `json:"ip"`
	Hosts []string `json:"hosts"`
}

// ReverseIP returns the host names HackerTarget observes on the given IP. The
// free tier has a small shared daily quota; when it is exhausted the endpoint
// replies with plaintext error prose rather than a host list, which is detected
// and surfaced as an error so the UI can say "source unavailable" rather than
// "no neighbours".
func ReverseIP(ctx context.Context, ip string) (*ReverseIPResult, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("invalid IP address %q", ip)
	}
	url := fmt.Sprintf("%s/reverseiplookup/?q=%s", ReverseIPBaseURL, ip)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", reverseIPUserAgent)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reverse-IP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reverse-IP lookup returned HTTP %d", resp.StatusCode)
	}

	seen := make(map[string]struct{})
	hosts := make([]string, 0, 32)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// The free tier signals quota/parameter problems with plaintext prose
		// ("API count exceeded …", "error check your search parameter"); these
		// contain spaces and are not host names, so treat their presence as a
		// failed lookup rather than silently returning nothing.
		low := strings.ToLower(line)
		if strings.Contains(low, "api count exceeded") || strings.HasPrefix(low, "error") {
			return nil, fmt.Errorf("reverse-IP source unavailable: %s", line)
		}
		host := strings.ToLower(strings.TrimSuffix(line, "."))
		// A valid host line is a single token with a dot and no whitespace.
		if strings.ContainsAny(host, " \t") || !strings.Contains(host, ".") {
			continue
		}
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reverse-IP response read failed: %w", err)
	}

	sort.Strings(hosts)
	return &ReverseIPResult{IP: ip, Hosts: hosts}, nil
}

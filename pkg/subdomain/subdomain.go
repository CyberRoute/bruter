// Package subdomain performs active subdomain discovery by brute-forcing a
// wordlist of candidate labels against a domain and keeping the ones that
// resolve. It complements the passive certificate-transparency sources in
// pkg/ssl: passive sources find names that were ever certificated, while
// brute-force finds live names that may never have appeared in CT logs.
package subdomain

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// defaultWordlistRaw is a curated list of common subdomain labels, embedded so
// the UI-triggered brute-force does not depend on a file path at runtime.
//
//go:embed wordlist.txt
var defaultWordlistRaw string

// defaultWorkers is the fan-out used when the caller passes workers <= 0. DNS
// resolution is I/O-bound, so a count well above the CPU count is appropriate.
const defaultWorkers = 50

// lookupTimeout bounds a single candidate's DNS resolution so one slow name
// cannot stall a worker.
const lookupTimeout = 3 * time.Second

// Result is a single resolved subdomain and the addresses it points to.
type Result struct {
	Host string   `json:"host"`
	IPs  []string `json:"ips"`
}

// BruteResult is the outcome of a brute-force run: the resolved subdomains plus
// metadata the UI needs to interpret them honestly (whether the zone uses
// wildcard DNS, and how many candidates were tested).
type BruteResult struct {
	Results  []Result `json:"results"`
	Wildcard bool     `json:"wildcard"`
	Tested   int      `json:"tested"`
}

// DefaultWords returns the embedded candidate labels.
func DefaultWords() []string {
	return splitWords(defaultWordlistRaw)
}

func splitWords(raw string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 256)
	for _, line := range strings.Split(raw, "\n") {
		w := strings.ToLower(strings.TrimSpace(line))
		// Skip blanks and comments; a bare label only (no dots/spaces).
		if w == "" || strings.HasPrefix(w, "#") || strings.ContainsAny(w, " \t") {
			continue
		}
		if _, dup := seen[w]; dup {
			continue
		}
		seen[w] = struct{}{}
		out = append(out, w)
	}
	return out
}

// resolver is the resolver used for all lookups; a package var so tests can
// substitute a mock.
var resolver = net.DefaultResolver

// detectWildcard probes several random, almost-certainly-nonexistent labels. If
// they resolve, the zone has a wildcard record and returns the union of the
// addresses it answers with, so genuine hits can be told apart from wildcard
// noise. It returns (false, nil) when no wildcard is in effect.
func detectWildcard(ctx context.Context, domain string) (bool, map[string]struct{}) {
	wildcardIPs := make(map[string]struct{})
	found := false
	for i := 0; i < 3; i++ {
		label := randomLabel() + "." + domain
		cctx, cancel := context.WithTimeout(ctx, lookupTimeout)
		addrs, err := resolver.LookupHost(cctx, label)
		cancel()
		if err == nil && len(addrs) > 0 {
			found = true
			for _, a := range addrs {
				wildcardIPs[a] = struct{}{}
			}
		}
	}
	if !found {
		return false, nil
	}
	return true, wildcardIPs
}

func randomLabel() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		// Fall back to a fixed-but-unlikely label; collision risk is negligible
		// for the purpose of wildcard detection.
		return "zzq7x3k9w1p4v2"
	}
	return "bruter" + hex.EncodeToString(b)
}

// BruteForce resolves <word>.<domain> for every word concurrently and returns
// the ones that resolve, filtering out wildcard-only matches. workers <= 0 uses
// a sensible default. The supplied ctx bounds the whole run.
func BruteForce(ctx context.Context, domain string, words []string, workers int) BruteResult {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	res := BruteResult{Tested: len(words), Results: []Result{}}
	if domain == "" || len(words) == 0 {
		return res
	}
	if workers <= 0 {
		workers = defaultWorkers
	}

	wildcard, wildcardIPs := detectWildcard(ctx, domain)
	res.Wildcard = wildcard

	jobs := make(chan string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for word := range jobs {
			host := word + "." + domain
			cctx, cancel := context.WithTimeout(ctx, lookupTimeout)
			addrs, err := resolver.LookupHost(cctx, host)
			cancel()
			if err != nil || len(addrs) == 0 {
				continue
			}
			// With a wildcard in effect, keep the host only if it answers with
			// at least one address outside the wildcard set — otherwise it is
			// the catch-all answering, not a real record.
			if wildcard && subsetOf(addrs, wildcardIPs) {
				continue
			}
			sort.Strings(addrs)
			mu.Lock()
			res.Results = append(res.Results, Result{Host: host, IPs: addrs})
			mu.Unlock()
		}
	}

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}

feed:
	for _, w := range words {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- w:
		}
	}
	close(jobs)
	wg.Wait()

	sort.Slice(res.Results, func(i, j int) bool { return res.Results[i].Host < res.Results[j].Host })
	return res
}

// subsetOf reports whether every address in addrs is present in the set.
func subsetOf(addrs []string, set map[string]struct{}) bool {
	for _, a := range addrs {
		if _, ok := set[a]; !ok {
			return false
		}
	}
	return true
}

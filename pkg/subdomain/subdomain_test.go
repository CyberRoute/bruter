package subdomain

import (
	"context"
	"testing"
)

func TestDefaultWords(t *testing.T) {
	words := DefaultWords()
	if len(words) == 0 {
		t.Fatal("DefaultWords() returned no labels")
	}
	seen := make(map[string]bool)
	for _, w := range words {
		if w == "" {
			t.Error("DefaultWords() contains an empty label")
		}
		if seen[w] {
			t.Errorf("DefaultWords() contains duplicate label %q", w)
		}
		seen[w] = true
	}
	if !seen["www"] || !seen["mail"] {
		t.Error("DefaultWords() missing expected common labels (www/mail)")
	}
}

func TestBruteForceLive(t *testing.T) {
	// example.com resolves on its apex but "www.example.com" also resolves,
	// so a tiny wordlist including "www" should yield at least that host and
	// must not flag the zone as a wildcard.
	res := BruteForce(context.Background(), "example.com", []string{"www", "nonexistent-xyz-label"}, 5)
	if res.Tested != 2 {
		t.Errorf("Tested = %d, want 2", res.Tested)
	}
	if res.Wildcard {
		t.Error("Wildcard = true for example.com, want false")
	}
	found := false
	for _, r := range res.Results {
		if r.Host == "www.example.com" {
			found = true
			if len(r.IPs) == 0 {
				t.Error("www.example.com resolved with no IPs recorded")
			}
		}
	}
	if !found {
		t.Error("BruteForce() did not resolve www.example.com")
	}
}

func TestBruteForceEmptyInput(t *testing.T) {
	if res := BruteForce(context.Background(), "", []string{"www"}, 1); len(res.Results) != 0 {
		t.Errorf("empty domain returned %d results, want 0", len(res.Results))
	}
	if res := BruteForce(context.Background(), "example.com", nil, 1); len(res.Results) != 0 {
		t.Errorf("nil wordlist returned %d results, want 0", len(res.Results))
	}
}

func TestSubsetOf(t *testing.T) {
	set := map[string]struct{}{"1.1.1.1": {}, "2.2.2.2": {}}
	if !subsetOf([]string{"1.1.1.1"}, set) {
		t.Error("subsetOf should be true when all addrs are in the set")
	}
	if subsetOf([]string{"1.1.1.1", "3.3.3.3"}, set) {
		t.Error("subsetOf should be false when an addr is outside the set")
	}
}

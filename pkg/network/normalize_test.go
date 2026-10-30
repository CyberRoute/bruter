package network

import "testing"

func TestNormalizeDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://www.msd.com", "msd.com"},
		{"http://www.msd.com/path?q=1", "msd.com"},
		{"www.msd.com", "msd.com"},
		{"www.msd.com:443", "msd.com"},
		{"WWW.MSD.COM", "msd.com"},
		{"https://WWW.MSD.COM/", "msd.com"},
		{"msd.com", "msd.com"},
		{"https://msd.com", "msd.com"},
		{"https://sub.msd.com", "sub.msd.com"}, // only www is stripped
		{"https://www.sub.msd.com", "sub.msd.com"},
		{"example.com.", "example.com"},
		{"  https://www.msd.com  ", "msd.com"},
		{"localhost:8080", "localhost"},
	}
	for _, tc := range cases {
		if got := NormalizeDomain(tc.in); got != tc.want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeDomainNeverEmptiesTarget(t *testing.T) {
	// A degenerate input must not be reduced to an empty domain.
	if got := NormalizeDomain("www."); got == "" {
		t.Fatal("sanitizeDomain returned an empty domain")
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1": true,
		"::1":       true,
		"localhost": true,
		"0.0.0.0":   false,
		"":          false, // all interfaces
		"192.0.2.1": false,
	} {
		if got := IsLoopbackAddr(addr); got != want {
			t.Errorf("IsLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

package network_test

import (
	"net"
	"testing"

	"github.com/CyberRoute/bruter/pkg/network"
)

func TestLookupDNS(t *testing.T) {
	t.Run("valid domain populates records", func(t *testing.T) {
		rec, err := network.LookupDNS("example.com")
		if err != nil {
			t.Fatalf("LookupDNS() unexpected error = %v", err)
		}
		if len(rec.A) == 0 && len(rec.AAAA) == 0 {
			t.Errorf("LookupDNS() returned no A/AAAA records for example.com")
		}
		for _, ip := range rec.A {
			if parsed := net.ParseIP(ip); parsed == nil || parsed.To4() == nil {
				t.Errorf("LookupDNS() A record = %q, want a valid IPv4 address", ip)
			}
		}
		if rec.MX == nil {
			t.Errorf("LookupDNS() MX map is nil, want initialised map")
		}
	})

	t.Run("unresolvable domain errors", func(t *testing.T) {
		if _, err := network.LookupDNS("inventatotrash.com"); err == nil {
			t.Errorf("LookupDNS() error = nil, want error for unresolvable domain")
		}
	})
}

func TestAttemptAXFRRefused(t *testing.T) {
	// A correctly configured zone refuses AXFR to arbitrary clients, so every
	// result must be non-vulnerable and carry an explanatory error. Uses live
	// name servers (consistent with the other tests in this package).
	rec, err := network.LookupDNS("example.com")
	if err != nil {
		t.Fatalf("LookupDNS() unexpected error = %v", err)
	}
	if len(rec.NS) == 0 {
		t.Skip("no NS records returned for example.com; cannot exercise AXFR path")
	}
	for _, z := range rec.AXFR {
		if z.Vulnerable {
			t.Errorf("AttemptAXFR() reported example.com NS %q as transfer-vulnerable", z.NS)
		}
		if z.Err == "" {
			t.Errorf("AttemptAXFR() non-vulnerable result for %q has empty error", z.NS)
		}
	}
}

func TestResolveByName(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{
			name:   "valid domain",
			domain: "example.com",
		},
		{
			name:    "invalid domain",
			domain:  "inventatotrash.com",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := network.ResolveByName(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResolveByName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			// Assert a resolvable IPv4 address rather than a hardcoded value,
			// which changes over time for shared hosts like example.com.
			ip := net.ParseIP(got)
			if ip == nil || ip.To4() == nil {
				t.Errorf("ResolveByName() = %q, want a valid IPv4 address", got)
			}
		})
	}
}

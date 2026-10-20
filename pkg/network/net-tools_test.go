package network_test

import (
	"net"
	"testing"

	"github.com/CyberRoute/bruter/pkg/network"
)

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

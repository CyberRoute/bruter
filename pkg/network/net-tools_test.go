package network_test

import (
	"testing"

	"github.com/CyberRoute/bruter/pkg/network"
)

func TestResolveByName(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		want    string
		wantErr bool
	}{
		{
			name:   "valid domain",
			domain: "example.com",
			want:   "93.184.216.34",
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
			if got != tt.want {
				t.Errorf("ResolveByName() = %v, want %v", got, tt.want)
			}
		})
	}
}

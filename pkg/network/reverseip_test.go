package network

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReverseIP(t *testing.T) {
	orig := ReverseIPBaseURL
	defer func() { ReverseIPBaseURL = orig }()

	t.Run("parses host list and dedups", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("example.com\nwww.example.com\nexample.com\nshared.example.net\n\n"))
		}))
		defer srv.Close()
		ReverseIPBaseURL = srv.URL

		res, err := ReverseIP(context.Background(), "93.184.216.34")
		if err != nil {
			t.Fatalf("ReverseIP() error = %v", err)
		}
		want := []string{"example.com", "shared.example.net", "www.example.com"}
		if len(res.Hosts) != len(want) {
			t.Fatalf("Hosts = %v, want %v", res.Hosts, want)
		}
		for i := range want {
			if res.Hosts[i] != want[i] {
				t.Errorf("Hosts[%d] = %q, want %q", i, res.Hosts[i], want[i])
			}
		}
	})

	t.Run("quota-exceeded prose is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("API count exceeded - Increase Quota with Membership"))
		}))
		defer srv.Close()
		ReverseIPBaseURL = srv.URL

		if _, err := ReverseIP(context.Background(), "93.184.216.34"); err == nil {
			t.Error("ReverseIP() error = nil, want error for quota-exceeded response")
		}
	})

	t.Run("invalid IP rejected before request", func(t *testing.T) {
		if _, err := ReverseIP(context.Background(), "not-an-ip"); err == nil {
			t.Error("ReverseIP() error = nil, want error for invalid IP")
		}
	})
}

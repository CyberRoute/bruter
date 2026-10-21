package network

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRobtexIPQuery(t *testing.T) {
	orig := RobtexBaseURL
	defer func() { RobtexBaseURL = orig }()

	t.Run("parses network info and sorts passive dns newest-first", func(t *testing.T) {
		body := `{"status":"ok","as":13335,"asname":"Cloudflare","bgproute":"104.20.16.0/20",
			"whoisdesc":"Cloudflare, Inc.",
			"act":[{"o":"example.com","t":200}],
			"pas":[{"o":"old.example.com","t":100},{"o":"new.example.com","t":300}]}`
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		defer srv.Close()
		RobtexBaseURL = srv.URL

		info, err := RobtexIPQuery(context.Background(), "104.20.23.154")
		if err != nil {
			t.Fatalf("RobtexIPQuery() error = %v", err)
		}
		if info.ASN != 13335 || info.ASName != "Cloudflare" {
			t.Errorf("ASN/ASName = %d/%q, want 13335/Cloudflare", info.ASN, info.ASName)
		}
		if len(info.Passive) != 2 || info.Passive[0].Host != "new.example.com" {
			t.Errorf("Passive not sorted newest-first: %+v", info.Passive)
		}
		if len(info.Active) != 1 || info.Active[0].Host != "example.com" {
			t.Errorf("Active = %+v, want single example.com", info.Active)
		}
	})

	t.Run("non-ok status is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"status":"ratelimited"}`))
		}))
		defer srv.Close()
		RobtexBaseURL = srv.URL

		if _, err := RobtexIPQuery(context.Background(), "104.20.23.154"); err == nil {
			t.Error("RobtexIPQuery() error = nil, want error for non-ok status")
		}
	})

	t.Run("invalid IP rejected before request", func(t *testing.T) {
		if _, err := RobtexIPQuery(context.Background(), "nope"); err == nil {
			t.Error("RobtexIPQuery() error = nil, want error for invalid IP")
		}
	})
}

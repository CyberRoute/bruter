package ssl

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFetchCertSpotterPaginates verifies that every page is walked via
// after=<last id>, and that a rate limit mid-walk keeps the partial results.
func TestFetchCertSpotterPaginates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		page := 0
		if a := r.URL.Query().Get("after"); a != "" {
			fmt.Sscanf(a, "%d", &page)
			page = page/certSpotterPageSize + 1
		}
		if page == 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		var items []string
		for i := 0; i < certSpotterPageSize; i++ {
			id := page*certSpotterPageSize + i
			items = append(items, fmt.Sprintf(`{"id":"%d","dns_names":["h%d.example.com"]}`, id, id))
		}
		_, _ = w.Write([]byte("[" + strings.Join(items, ",") + "]"))
	}))
	defer srv.Close()
	orig := CertSpotterBaseURL
	CertSpotterBaseURL = srv.URL
	defer func() { CertSpotterBaseURL = orig }()

	data, err := fetchCertSpotter(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 2*certSpotterPageSize {
		t.Fatalf("want %d records from 2 pages, got %d", 2*certSpotterPageSize, len(data))
	}
}

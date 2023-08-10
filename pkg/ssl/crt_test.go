package ssl_test

import (
	"github.com/CyberRoute/bruter/pkg/ssl"
	"testing"
)

func TestFetchCrtData(t *testing.T) {
	domain := "example.com"
	data, err := ssl.FetchCrtData(domain)
	if err != nil {
		t.Fatalf("Failed to fetch data: %v", err)
	}

	if len(data) == 0 {
		t.Errorf("Fetched data is empty")
	}
}

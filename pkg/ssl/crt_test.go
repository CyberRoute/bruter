package ssl_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CyberRoute/bruter/pkg/ssl"
)

func TestFetchCrtData(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a response here (useful for testing different scenarios)
		data := `[{"field1": "value1"}, {"field2": "value2"}]`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(data))
	}))
	defer mockServer.Close()

	data, err := ssl.FetchCrtData("example.com")
	if err != nil {
		t.Fatalf("Failed to fetch data: %v", err)
	}

	if len(data) == 0 {
		t.Errorf("Fetched data is empty")
	}
}

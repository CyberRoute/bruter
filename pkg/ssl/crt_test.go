package ssl

import (
	"net/http"
	"net/http/httptest"
	"testing"
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

	// Isolate all other sources (concurrent merge would otherwise hit the real
	// network) and point crt.sh at the mock server.
	defer isolateSources()()
	CrtBaseURL = mockServer.URL

	data, err := FetchCrtData("example.com")
	if err != nil {
		t.Fatalf("Failed to fetch data: %v", err)
	}

	if len(data) == 0 {
		t.Errorf("Fetched data is empty")
	}
}

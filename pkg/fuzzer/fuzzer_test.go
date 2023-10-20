package fuzzer_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/CyberRoute/bruter/pkg/fuzzer"
)

func TestGet(t *testing.T) {
	// Create a mock HTTP server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Respond with a mock JSON response
		response := map[string]interface{}{
			"key": "value",
		}
		err := json.NewEncoder(w).Encode(response)
		if err != nil {
			t.Fatalf("Error encoding JSON response: %v", err)
		}
	}))
	defer server.Close()

	// Set up test input parameters
	Mu := &sync.Mutex{}
	path := "/test"
	progress := float32(0.5)
	verbose := true

	domain := strings.TrimPrefix(server.URL, "https://")

	// Call the Get function with the mock server URL
	fuzzer.Get(Mu, domain, path, progress, verbose)
}

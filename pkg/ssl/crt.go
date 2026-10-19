package ssl

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// CrtBaseURL is the crt.sh endpoint. It is a variable so tests can point it at
// a mock server.
var CrtBaseURL = "https://crt.sh"

func FetchCrtData(domain string) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("%s/?q=%s&output=json", CrtBaseURL, domain)

	response, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh unavailable: HTTP %d", response.StatusCode)
	}

	// crt.sh serves an HTML error page (not JSON) when it is overloaded; detect
	// that early so the caller gets a clear message instead of a JSON parse error.
	if ct := response.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
		return nil, fmt.Errorf("crt.sh returned a non-JSON response (service may be down)")
	}

	var data []map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("crt.sh response decode failed: %w", err)
	}
	return data, nil
}

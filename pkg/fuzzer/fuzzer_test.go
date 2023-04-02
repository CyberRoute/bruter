package fuzzer_test

import (
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/CyberRoute/bruter/pkg/fuzzer"
)

func TestUrlJoin(t *testing.T) {
	uri := "https://example.com"
	urj := "/path/to/something"

	expected := "https://example.com/path/to/something"

	result, err := fuzzer.UrlJoin(uri, urj)
	if err != nil {
		t.Errorf("urlJoin(%s, %s) returned error: %v", uri, urj, err)
	}

	if result != expected {
		t.Errorf("urlJoin(%s, %s) = %s, expected %s", uri, urj, result, expected)
	}
}

func TestAuth(t *testing.T) {
	// create a listener with the desired port.
	l, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		log.Fatal(err)
	}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ts.Listener.Close()
	ts.Listener = l

	// Start the server.
	ts.Start()

	// Test 1 - valid URL
	progress := float32(0.5)

	// Create a test server that returns a 200 status code
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer testServer.Close()

	domain := testServer.URL[7:] // Remove the "http://" prefix
	path := "/"

	go fuzzer.Auth(&sync.Mutex{}, domain, path, progress, true)

	// Test 3 - 403 status code
	progress = float32(0.5)

	// Create a test server that returns a 403 status code
	testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer testServer.Close()

	domain = testServer.URL[7:] // Remove the "http://" prefix
	path = "/"

	go fuzzer.Auth(&sync.Mutex{}, domain, path, progress, true)

	// Test 4 - non-200, non-403 status code
	progress = float32(0.5)

	// Create a test server that returns a 500 status code
	testServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer testServer.Close()

	domain = testServer.URL[7:] // Remove the "http://" prefix
	path = "/"

	go fuzzer.Auth(&sync.Mutex{}, domain, path, progress, true)

	ts.Close()
}

package fuzzer

import (
	"errors"
	"net/url"
	"strings"
)

func NormalizeURL(base string) (string, error) {
	if base == "" {
		return "", errors.New("URL is empty")
	}

	// Parse the URL
	parsedURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	// Ensure the scheme is set to either "http" or "https"
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		parsedURL.Scheme = "http"
	}

	// Ensure there's a trailing slash in the path
	if parsedURL.Path == "" || !strings.HasSuffix(parsedURL.Path, "/") {
		parsedURL.Path += "/"
	}

	// Update the original string
	base = parsedURL.String()

	return base, nil
}

package fuzzer

import (
	"errors"
	"net/url"
)

func NormalizeURL(base, scheme string) (string, error) {
	if base == "" {
		return "", errors.New("URL is empty")
	}

	// Default to http only when no valid scheme was supplied.
	if scheme != "http" && scheme != "https" {
		scheme = "http"
	}

	// Parse the URL
	parsedURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	// Ensure the scheme is set to either "http" or "https"
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		parsedURL.Scheme = scheme
	}

	// Update the original string
	base = parsedURL.String()

	return base, nil
}

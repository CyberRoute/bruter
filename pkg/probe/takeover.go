package probe

import (
	_ "embed"
	"encoding/json"
	"strings"
)

// fingerprintsRaw is the embedded subdomain-takeover fingerprint database,
// curated from the public can-i-take-over-xyz dataset. Each entry maps a set of
// CNAME targets for a hosting service to a body signature that the service
// returns when the claimed name is unprovisioned.
//
//go:embed fingerprints.json
var fingerprintsRaw []byte

// Fingerprint is one takeover signature: a host whose CNAME points at one of
// Cnames and whose response body contains Fingerprint is a candidate takeover.
type Fingerprint struct {
	Service     string   `json:"service"`
	Cnames      []string `json:"cnames"`
	Fingerprint string   `json:"fingerprint"`
}

// fingerprints is the parsed database, loaded once at init.
var fingerprints = loadFingerprints()

func loadFingerprints() []Fingerprint {
	var fps []Fingerprint
	// The database is embedded and trusted, so a parse failure is a build-time
	// bug; fall back to an empty set rather than panicking in a server.
	_ = json.Unmarshal(fingerprintsRaw, &fps)
	return fps
}

// Takeover is the result of a subdomain-takeover check for one host.
type Takeover struct {
	Vulnerable bool   `json:"vulnerable"`
	Service    string `json:"service"`
	CNAME      string `json:"cname"`
	Evidence   string `json:"evidence"`
}

// checkTakeover decides whether a host is a takeover candidate given its CNAME
// target and the response body fetched from it. A candidate requires both that
// the CNAME points at a known service and that the body carries that service's
// "unclaimed" signature — the two-signal rule that keeps false positives down.
// A CNAME that matches a service but whose body lacks the signature is reported
// as a non-vulnerable match (Service set, Vulnerable false) so the UI can still
// surface "points at <service>, verify manually".
func checkTakeover(cname, body string) *Takeover {
	cname = strings.ToLower(strings.TrimSuffix(cname, "."))
	if cname == "" {
		return nil
	}
	lowerBody := strings.ToLower(body)

	for _, fp := range fingerprints {
		matchedService := false
		for _, c := range fp.Cnames {
			if strings.Contains(cname, strings.ToLower(c)) {
				matchedService = true
				break
			}
		}
		if !matchedService {
			continue
		}
		t := &Takeover{Service: fp.Service, CNAME: cname}
		// An empty fingerprint means the service is claimable purely on the
		// CNAME pointing at an unprovisioned target; flag for manual review
		// rather than asserting exploitability.
		if fp.Fingerprint != "" && strings.Contains(lowerBody, strings.ToLower(fp.Fingerprint)) {
			t.Vulnerable = true
			t.Evidence = fp.Fingerprint
		}
		return t
	}
	return nil
}

// FingerprintCount reports how many takeover signatures are loaded (used by
// tests and diagnostics).
func FingerprintCount() int { return len(fingerprints) }

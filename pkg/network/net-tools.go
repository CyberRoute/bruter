package network

import (
	"crypto/tls"
	"fmt"
	"github.com/likexian/whois"
	"html/template"
	"net"
	"net/http"
	"strings"
	"time"
)

// DetectScheme probes the domain root over HTTPS, then HTTP, and returns the
// scheme that accepts a connection ("https" preferred). Redirects are not
// followed and certificates are not verified. If neither responds it defaults
// to "https", since modern hosts are typically HTTPS-only.
func DetectScheme(domain string) string {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // scanner probes untrusted hosts by design
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, scheme := range []string{"https", "http"} {
		resp, err := client.Head(scheme + "://" + domain + "/")
		if err == nil {
			_ = resp.Body.Close()
			return scheme
		}
	}
	return "https"
}

func ResolveByName(domain string) (string, error) {
	ip4address, err := net.ResolveIPAddr("ip4", domain)
	if err != nil {
		return "", fmt.Errorf("failed to resolve IPv4 address: %v", err)
	}
	return ip4address.String(), nil
}

func ResolveByNameipv6(domain string) (string, error) {
	ip6address, err := net.ResolveIPAddr("ip6", domain)
	if err != nil {
		return "not found", fmt.Errorf("failed to resolve IPv6 address: %v", err)
	}
	return ip6address.String(), nil
}

// DNSRecords is the collected DNS view of a domain returned by LookupDNS and
// served as JSON to the UI. Each slice is nil/empty when that record type is
// absent or the individual lookup fails, so a single failing record type does
// not blank out the others.
type DNSRecords struct {
	A     []string          `json:"a"`
	AAAA  []string          `json:"aaaa"`
	NS    []string          `json:"ns"`
	TXT   []string          `json:"txt"`
	CNAME string            `json:"cname"`
	MX    map[string]uint16 `json:"mx"`
	PTR   []string          `json:"ptr"`
	SOA   *SOARecord        `json:"soa,omitempty"`
	AXFR  []ZoneTransfer    `json:"axfr,omitempty"`
	Email *EmailAuth        `json:"email,omitempty"`
}

// LookupDNS gathers common DNS records (A, AAAA, NS, TXT, CNAME, MX) plus the
// reverse-DNS (PTR) names of the first A record using the stdlib resolver. It
// is best-effort: individual record-type failures (e.g. NXDOMAIN for TXT) are
// swallowed so the remaining records still populate. It returns an error only
// when the domain resolves to nothing at all, which the caller surfaces as a
// failed lookup rather than an empty-but-OK result.
func LookupDNS(domain string) (*DNSRecords, error) {
	rec := &DNSRecords{MX: map[string]uint16{}}

	if ips, err := net.LookupIP(domain); err == nil {
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				rec.A = append(rec.A, v4.String())
			} else {
				rec.AAAA = append(rec.AAAA, ip.String())
			}
		}
	}

	if nss, err := net.LookupNS(domain); err == nil {
		for _, ns := range nss {
			rec.NS = append(rec.NS, strings.TrimSuffix(ns.Host, "."))
		}
	}

	if txts, err := net.LookupTXT(domain); err == nil {
		rec.TXT = txts
	}

	// A CNAME equal to the queried name (with trailing dot) means no real
	// alias exists, so only record a genuine alias.
	if cname, err := net.LookupCNAME(domain); err == nil {
		if trimmed := strings.TrimSuffix(cname, "."); trimmed != "" && !strings.EqualFold(trimmed, domain) {
			rec.CNAME = trimmed
		}
	}

	if mxs, err := net.LookupMX(domain); err == nil {
		for _, mx := range mxs {
			rec.MX[strings.TrimSuffix(mx.Host, ".")] = mx.Pref
		}
	}

	// Reverse-DNS the first IPv4 address (fall back to the first IPv6) so the
	// UI can show which host name the address maps back to.
	var ptrTarget string
	if len(rec.A) > 0 {
		ptrTarget = rec.A[0]
	} else if len(rec.AAAA) > 0 {
		ptrTarget = rec.AAAA[0]
	}
	if ptrTarget != "" {
		if names, err := net.LookupAddr(ptrTarget); err == nil {
			for _, n := range names {
				rec.PTR = append(rec.PTR, strings.TrimSuffix(n, "."))
			}
		}
	}

	if len(rec.A) == 0 && len(rec.AAAA) == 0 && len(rec.NS) == 0 &&
		len(rec.TXT) == 0 && rec.CNAME == "" && len(rec.MX) == 0 {
		return nil, fmt.Errorf("no DNS records found for domain %s", domain)
	}

	// Authoritative-data checks (SOA via a resolver, AXFR against each NS) run
	// after the basic records so a resolver outage or a refused transfer never
	// blanks out the records we already have.
	rec.SOA = LookupSOA(domain)
	if len(rec.NS) > 0 {
		rec.AXFR = AttemptAXFR(domain, rec.NS)
	}

	// Email-authentication verdict: SPF comes from the TXT records already
	// fetched; DMARC is looked up separately inside AnalyzeEmailAuth.
	rec.Email = AnalyzeEmailAuth(domain, rec.TXT)
	return rec, nil
}

func FindMX(domain string) (map[string]uint16, error) {
	mx_records := make(map[string]uint16)
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve mx records: %v", err)
	}
	if len(mxRecords) <= 1 {
		return nil, fmt.Errorf("no MX records found for domain %s", domain)
	}
	for _, mxRecord := range mxRecords {
		mx_records[mxRecord.Host] = mxRecord.Pref
	}
	return mx_records, nil
}

// WhoisLookupRaw returns the unmodified WHOIS text for a domain. It is intended
// for JSON API consumers (e.g. the React UI) that escape the value themselves;
// unlike WhoisLookup it performs no HTML escaping or <br> substitution.
func WhoisLookupRaw(domain string) (string, error) {
	result, err := whois.Whois(domain)
	if err != nil {
		return "", fmt.Errorf("failed to perform WHOIS lookup: %v", err)
	}
	return result, nil
}

func WhoisLookup(domain string) (template.HTML, error) {
	result, err := whois.Whois(domain)
	if err != nil {
		return "", fmt.Errorf("failed to perform WHOIS lookup: %v", err)
	}
	// WHOIS output is attacker-influenceable (registration fields of a malicious
	// domain), so escape it before marking it safe HTML, then turn newlines into
	// <br> for display.
	escaped := template.HTMLEscapeString(result)
	escaped = strings.ReplaceAll(escaped, "\n", "<br>")
	return template.HTML(escaped), nil
}

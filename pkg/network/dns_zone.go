package network

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// axfrRecordCap bounds how many resource records a single zone transfer will
// collect so a large (or deliberately oversized) zone cannot exhaust memory.
// The point of the check is to prove the transfer succeeds, not to mirror the
// whole zone, so a generous-but-finite cap is sufficient.
const axfrRecordCap = 500

// SOARecord is the parsed Start-of-Authority record for a zone. Serial is the
// most useful field for a hunter (it dates the zone and distinguishes stale
// delegations); the timers hint at how aggressively the zone is refreshed.
type SOARecord struct {
	NS      string `json:"ns"`
	Mbox    string `json:"mbox"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	MinTTL  uint32 `json:"min_ttl"`
}

// ZoneTransfer records the outcome of attempting an AXFR against one of the
// domain's authoritative name servers. Vulnerable is true when the server
// answered with zone data — a misconfiguration that leaks the entire zone
// (every subdomain, internal host and record) to an unauthenticated client.
type ZoneTransfer struct {
	NS         string   `json:"ns"`
	Vulnerable bool     `json:"vulnerable"`
	Records    []string `json:"records,omitempty"`
	Truncated  bool     `json:"truncated,omitempty"`
	Err        string   `json:"error,omitempty"`
}

// resolverAddr returns a "host:53" resolver address: the first nameserver from
// the system resolver config, falling back to Cloudflare then Google when the
// config is empty or unreadable (common on macOS, where /etc/resolv.conf may
// not list servers).
func resolverAddr() string {
	if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
		port := cfg.Port
		if port == "" {
			port = "53"
		}
		return net.JoinHostPort(cfg.Servers[0], port)
	}
	return "1.1.1.1:53"
}

// LookupSOA queries the SOA record for domain via a recursive resolver. It is
// best-effort: any failure (no SOA, resolver down) returns nil so callers can
// treat the SOA as simply absent without aborting the wider DNS collection.
func LookupSOA(domain string) *SOARecord {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	m.RecursionDesired = true

	c := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := c.Exchange(m, resolverAddr())
	if err != nil || resp == nil {
		return nil
	}
	for _, ans := range resp.Answer {
		if soa, ok := ans.(*dns.SOA); ok {
			return &SOARecord{
				NS:      strings.TrimSuffix(soa.Ns, "."),
				Mbox:    strings.TrimSuffix(soa.Mbox, "."),
				Serial:  soa.Serial,
				Refresh: soa.Refresh,
				Retry:   soa.Retry,
				Expire:  soa.Expire,
				MinTTL:  soa.Minttl,
			}
		}
	}
	return nil
}

// AttemptAXFR tries a full zone transfer (AXFR) against each of the supplied
// name servers and reports, per server, whether the zone was handed over. A
// successful transfer is a real, reportable finding (full-zone disclosure), so
// this is an active check intended for authorised targets only. Records are
// capped at axfrRecordCap per server; nameservers is typically rec.NS.
func AttemptAXFR(domain string, nameservers []string) []ZoneTransfer {
	results := make([]ZoneTransfer, 0, len(nameservers))
	for _, ns := range nameservers {
		ns = strings.TrimSuffix(ns, ".")
		if ns == "" {
			continue
		}
		results = append(results, attemptAXFROne(domain, ns))
	}
	return results
}

func attemptAXFROne(domain, ns string) ZoneTransfer {
	res := ZoneTransfer{NS: ns}

	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))

	t := &dns.Transfer{DialTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second}
	ch, err := t.In(m, net.JoinHostPort(ns, "53"))
	if err != nil {
		res.Err = err.Error()
		return res
	}

	for env := range ch {
		if env.Error != nil {
			// A refused/closed transfer is the healthy, expected case; record
			// it as the server's error rather than as a vulnerability.
			if res.Err == "" {
				res.Err = env.Error.Error()
			}
			continue
		}
		for _, rr := range env.RR {
			if len(res.Records) >= axfrRecordCap {
				res.Truncated = true
				break
			}
			res.Records = append(res.Records, rr.String())
		}
	}

	res.Vulnerable = len(res.Records) > 0
	if res.Vulnerable {
		// Zone data arrived, so any earlier transient error is noise.
		res.Err = ""
	} else if res.Err == "" {
		res.Err = fmt.Sprintf("no zone data returned by %s", ns)
	}
	return res
}

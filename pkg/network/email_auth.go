package network

import (
	"net"
	"strconv"
	"strings"
)

// EmailAuth is a verdict on a domain's email-authentication posture, derived
// from its SPF (a TXT record on the apex) and DMARC (a TXT record on the
// _dmarc subdomain). Spoofable summarises the bug-bounty-relevant question:
// can an attacker send From: this domain and have it pass authentication at a
// typical receiver?
type EmailAuth struct {
	SPF       *SPFResult   `json:"spf"`
	DMARC     *DMARCResult `json:"dmarc"`
	Spoofable bool         `json:"spoofable"`
	Summary   string       `json:"summary"`
}

// SPFResult is the parsed SPF record. Qualifier is the qualifier on the final
// "all" mechanism — the catch-all policy applied to senders not otherwise
// matched: "-" (hardfail), "~" (softfail), "?" (neutral), "+" (pass, i.e. any
// sender allowed).
type SPFResult struct {
	Present   bool     `json:"present"`
	Record    string   `json:"record"`
	Qualifier string   `json:"qualifier"`
	Issues    []string `json:"issues"`
}

// DMARCResult is the parsed DMARC record. Policy is the p= value
// (none/quarantine/reject); SubdomainPolicy is sp= when present. Pct is the
// percentage of mail the policy is applied to (defaults to 100).
type DMARCResult struct {
	Present         bool     `json:"present"`
	Record          string   `json:"record"`
	Policy          string   `json:"policy"`
	SubdomainPolicy string   `json:"subdomain_policy"`
	Pct             int      `json:"pct"`
	Issues          []string `json:"issues"`
}

// dmarcLookup is the resolver call used to fetch the _dmarc TXT record; a var
// so tests can stub it.
var dmarcLookup = net.LookupTXT

// AnalyzeEmailAuth derives an EmailAuth verdict for domain. It reads SPF from
// the already-fetched apex TXT records (passed in to avoid a duplicate lookup)
// and performs its own lookup for the _dmarc TXT record. It is best-effort: a
// failed DMARC lookup is treated as "no DMARC", which is itself the finding.
func AnalyzeEmailAuth(domain string, apexTXT []string) *EmailAuth {
	spf := parseSPF(apexTXT)

	var dmarcTXT []string
	if recs, err := dmarcLookup("_dmarc." + domain); err == nil {
		dmarcTXT = recs
	}
	dmarc := parseDMARC(dmarcTXT)

	ea := &EmailAuth{SPF: spf, DMARC: dmarc}

	// A domain is practically spoofable (From-header spoofing that passes
	// receiver checks) when DMARC is absent or set to p=none: SPF alone does
	// not prevent From spoofing because, without DMARC, receivers do not
	// enforce alignment between the authenticated domain and the visible From.
	switch {
	case !dmarc.Present:
		ea.Spoofable = true
		ea.Summary = "No DMARC record: the domain is spoofable (SPF alone does not stop From-header spoofing)."
	case dmarc.Policy == "none":
		ea.Spoofable = true
		ea.Summary = "DMARC p=none: policy is monitor-only, so spoofed mail is not rejected or quarantined."
	case dmarc.Policy == "quarantine":
		ea.Spoofable = false
		ea.Summary = "DMARC p=quarantine: spoofed mail is quarantined."
	case dmarc.Policy == "reject":
		ea.Spoofable = false
		ea.Summary = "DMARC p=reject: spoofed mail is rejected (strongest posture)."
	default:
		ea.Spoofable = true
		ea.Summary = "DMARC present but policy could not be determined; treat as spoofable until confirmed."
	}
	if !spf.Present {
		ea.Summary += " No SPF record is published."
	}
	return ea
}

func parseSPF(txt []string) *SPFResult {
	res := &SPFResult{Issues: []string{}}
	for _, r := range txt {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), "v=spf1") {
			continue
		}
		res.Present = true
		res.Record = strings.TrimSpace(r)
		res.Qualifier = spfAllQualifier(res.Record)
		switch res.Qualifier {
		case "+":
			res.Issues = append(res.Issues, "+all allows any host to send as this domain (effectively no protection)")
		case "?":
			res.Issues = append(res.Issues, "?all is neutral: senders are neither passed nor failed")
		case "~":
			res.Issues = append(res.Issues, "~all is softfail: mail is accepted and merely marked")
		case "":
			res.Issues = append(res.Issues, "no 'all' mechanism: SPF does not define a default policy")
		}
		return res
	}
	res.Issues = append(res.Issues, "no SPF record published")
	return res
}

// spfAllQualifier returns the qualifier character on the final "all" mechanism
// of an SPF record ("-", "~", "?", "+"), or "" if there is no all mechanism.
func spfAllQualifier(record string) string {
	for _, tok := range strings.Fields(record) {
		switch strings.ToLower(tok) {
		case "all":
			return "+" // bare "all" means pass
		case "-all":
			return "-"
		case "~all":
			return "~"
		case "?all":
			return "?"
		case "+all":
			return "+"
		}
	}
	return ""
}

func parseDMARC(txt []string) *DMARCResult {
	res := &DMARCResult{Pct: 100, Issues: []string{}}
	for _, r := range txt {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), "v=dmarc1") {
			continue
		}
		res.Present = true
		res.Record = strings.TrimSpace(r)
		for _, part := range strings.Split(res.Record, ";") {
			kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(kv[0]))
			val := strings.ToLower(strings.TrimSpace(kv[1]))
			switch key {
			case "p":
				res.Policy = val
			case "sp":
				res.SubdomainPolicy = val
			case "pct":
				if n, err := strconv.Atoi(val); err == nil {
					res.Pct = n
				}
			}
		}
		if res.Policy == "none" {
			res.Issues = append(res.Issues, "p=none is monitor-only and does not block spoofed mail")
		}
		if res.Pct < 100 && res.Pct >= 0 {
			res.Issues = append(res.Issues, "pct<100: the policy is applied to only a fraction of mail")
		}
		if res.SubdomainPolicy == "none" {
			res.Issues = append(res.Issues, "sp=none leaves subdomains unprotected")
		}
		return res
	}
	res.Issues = append(res.Issues, "no DMARC record published")
	return res
}

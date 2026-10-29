package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/CyberRoute/bruter/pkg/crawl"
	"github.com/CyberRoute/bruter/pkg/models"
	"github.com/CyberRoute/bruter/pkg/network"
	"github.com/CyberRoute/bruter/pkg/probe"
	"github.com/CyberRoute/bruter/pkg/ssl"
	"github.com/CyberRoute/bruter/pkg/subdomain"
	"github.com/CyberRoute/bruter/pkg/xss"
	"github.com/go-chi/chi/v5"
)

// hostInfo is the JSON shape served to the React UI for the dashboard. It is a
// flattened, client-friendly projection of models.HomeArgs (headers reduced to
// strings, banners collapsed into a single map keyed by service).
type hostInfo struct {
	Domain     string            `json:"domain"`
	Ipv4       string            `json:"ipv4"`
	Ipv6       string            `json:"ipv6"`
	Asn        string            `json:"asn"`
	City       string            `json:"city"`
	Country    string            `json:"country"`
	Isp        string            `json:"isp"`
	Org        string            `json:"org"`
	RegionCode string            `json:"region_code"`
	Ports      []int             `json:"ports"`
	Mx         map[string]uint16 `json:"mx"`
	Headers    map[string]string `json:"headers"`
	Banners    map[string]string `json:"banners"`
}

// writeJSON encodes v as JSON, logging (rather than panicking) on failure so a
// late encode error cannot take down the request via the Recoverer middleware.
func (m *Repository) writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		m.App.ZeroLog.Error().Err(err).Msg("failed to encode JSON response")
	}
}

// flattenHeaders turns http.Header-style values ([]string) into a single
// comma-joined string per header name for simpler client rendering.
func flattenHeaders(in map[string]interface{}) map[string]string {
	out := make(map[string]string, len(in))
	for name, v := range in {
		switch val := v.(type) {
		case []string:
			out[name] = strings.Join(val, ", ")
		case string:
			out[name] = val
		default:
			continue
		}
	}
	return out
}

// HostAPI serves the dashboard host/network data gathered once at startup.
func (m *Repository) HostAPI(args models.HomeArgs) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		banners := map[string]string{}
		for svc, val := range map[string]string{
			"mysql": args.Mysql,
			"ftp":   args.Ftp,
			"ssh":   args.Ssh,
			"smtp":  args.Smtp,
			"pop":   args.Pop,
			"irc":   args.Irc,
		} {
			if strings.TrimSpace(val) != "" {
				banners[svc] = val
			}
		}

		m.writeJSON(w, hostInfo{
			Domain:     m.App.Domain,
			Ipv4:       args.Ipv4,
			Ipv6:       args.Ipv6,
			Asn:        args.Host.Asn,
			City:       args.Host.City,
			Country:    args.Host.CountryName,
			Isp:        args.Host.Isp,
			Org:        args.Host.Org,
			RegionCode: args.Host.RegionCode,
			Ports:      args.Host.Ports,
			Mx:         args.Mx,
			Headers:    flattenHeaders(args.Headers),
			Banners:    banners,
		})
	}
}

// SSLAPI serves certificate-transparency records (crt.sh and fallbacks). When
// every source fails (e.g. all aggregators rate-limited), it responds 502 with
// an error message so the UI can distinguish "sources unavailable, retry" from
// a genuinely empty result rather than silently showing "no subdomains".
func (m *Repository) SSLAPI(w http.ResponseWriter, r *http.Request) {
	sslInfo, err := ssl.FetchCrtData(m.App.Domain)
	if err != nil {
		m.checkError(err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		if encErr := json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}); encErr != nil {
			m.App.ZeroLog.Error().Err(encErr).Msg("failed to encode SSL error response")
		}
		return
	}
	if sslInfo == nil {
		sslInfo = []map[string]interface{}{}
	}
	m.writeJSON(w, sslInfo)
}

// DNSAPI serves the domain's DNS records (A/AAAA/NS/TXT/CNAME/MX/PTR). When the
// domain resolves to nothing it responds 502 with an error message so the UI
// can distinguish a failed lookup from a genuinely sparse record set, matching
// SSLAPI's behaviour.
func (m *Repository) DNSAPI(w http.ResponseWriter, r *http.Request) {
	rec, err := network.LookupDNS(m.App.Domain)
	if err != nil {
		m.checkError(err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		if encErr := json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}); encErr != nil {
			m.App.ZeroLog.Error().Err(encErr).Msg("failed to encode DNS error response")
		}
		return
	}
	m.writeJSON(w, rec)
}

// bruteSubdomainsTimeout bounds a whole brute-force run so a slow resolver or
// an unusually large wordlist cannot hold the request open indefinitely.
const bruteSubdomainsTimeout = 60 * time.Second

// SubdomainBruteAPI actively brute-forces common subdomain labels against the
// scanned domain and returns the ones that resolve. This is an active probe
// (DNS resolution of guessed names), unlike the passive /api/ssl source. The
// response reports whether the zone uses wildcard DNS so the UI can caveat the
// results, and how many candidates were tested.
func (m *Repository) SubdomainBruteAPI(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), bruteSubdomainsTimeout)
	defer cancel()

	result := subdomain.BruteForce(ctx, m.App.Domain, subdomain.DefaultWords(), 0)
	m.writeJSON(w, result)
}

// reverseIPTimeout bounds the external reverse-IP lookup.
const reverseIPTimeout = 20 * time.Second

// ReverseIPAPI resolves the scanned domain to an IPv4 address and returns the
// other host names sharing that IP ("neighbours"), via an external source. On
// a resolve failure or an unavailable source it responds 502 with an error
// message, matching the other external-source endpoints.
func (m *Repository) ReverseIPAPI(w http.ResponseWriter, r *http.Request) {
	ip, err := network.ResolveByName(m.App.Domain)
	if err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), reverseIPTimeout)
		defer cancel()
		var result *network.ReverseIPResult
		result, err = network.ReverseIP(ctx, ip)
		if err == nil {
			m.writeJSON(w, result)
			return
		}
	}

	m.checkError(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	if encErr := json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}); encErr != nil {
		m.App.ZeroLog.Error().Err(encErr).Msg("failed to encode reverse-IP error response")
	}
}

// RobtexAPI resolves the scanned domain and returns Robtex's comprehensive
// view of its IP (network ownership plus active/passive DNS). On a resolve
// failure or unavailable source it responds 502 with an error message.
func (m *Repository) RobtexAPI(w http.ResponseWriter, r *http.Request) {
	ip, err := network.ResolveByName(m.App.Domain)
	if err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), reverseIPTimeout)
		defer cancel()
		var info *network.RobtexIPInfo
		info, err = network.RobtexIPQuery(ctx, ip)
		if err == nil {
			m.writeJSON(w, info)
			return
		}
	}

	m.checkError(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	if encErr := json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}); encErr != nil {
		m.App.ZeroLog.Error().Err(encErr).Msg("failed to encode robtex error response")
	}
}

// maxProbeHosts caps how many hosts a single probe request will process so a
// large discovered set cannot tie up the server indefinitely.
const maxProbeHosts = 300

// probeTimeout bounds the whole probe run.
const probeTimeout = 90 * time.Second

// ProbeAPI performs HTTP probing and subdomain-takeover checks on a client-
// supplied list of hosts (POST { "hosts": [...] }). The list comes from the
// UI's already-discovered subdomains, keeping discovery and probing decoupled.
// This is an active check: it makes HTTP requests to each host.
func (m *Repository) ProbeAPI(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hosts []string `json:"hosts"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		if encErr := json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body: " + err.Error()}); encErr != nil {
			m.App.ZeroLog.Error().Err(encErr).Msg("failed to encode probe error response")
		}
		return
	}
	if len(req.Hosts) > maxProbeHosts {
		req.Hosts = req.Hosts[:maxProbeHosts]
	}

	ctx, cancel := context.WithTimeout(r.Context(), probeTimeout)
	defer cancel()

	results := probe.ProbeHosts(ctx, req.Hosts, 0)
	m.writeJSON(w, results)
}

// xssScanTimeout bounds a whole dalfox run so a slow or stuck scan cannot hold
// the request open indefinitely.
const xssScanTimeout = 120 * time.Second

// writeAPIError writes { "error": msg } with the given status, logging an
// encode failure rather than letting it escape.
func (m *Repository) writeAPIError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
		m.App.ZeroLog.Error().Err(err).Msg("failed to encode error response")
	}
}

// XSSAPI runs the external dalfox scanner against a client-supplied URL
// (POST { "url": "https://host/path?param=value" }) and returns the findings.
// This is an active check: dalfox sends live XSS payloads to the target, so the
// URL is caller-supplied and opt-in from the UI. When dalfox is not installed
// the response is 501 with a distinct { "error": ..., "dalfox_installed": false }
// so the UI can show an install hint rather than a generic failure.
func (m *Repository) XSSAPI(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL        string `json:"url"`
		SkipMining bool   `json:"skip_mining"`
		Cookie     string `json:"cookie"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		m.writeAPIError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), xssScanTimeout)
	defer cancel()

	result, err := xss.Scan(ctx, req.URL, xss.Options{SkipMining: req.SkipMining, Cookie: req.Cookie})
	if err != nil {
		m.checkError(err)
		if errors.Is(err, xss.ErrNotInstalled) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotImplemented)
			if encErr := json.NewEncoder(w).Encode(map[string]interface{}{
				"error":            err.Error(),
				"dalfox_installed": false,
			}); encErr != nil {
				m.App.ZeroLog.Error().Err(encErr).Msg("failed to encode xss error response")
			}
			return
		}
		m.writeAPIError(w, http.StatusBadGateway, err.Error())
		return
	}
	m.writeJSON(w, result)
}

// --- Crawl + automated multi-target scanning -------------------------------

// crawlTimeout bounds a whole crawl so a large or slow site cannot hold the
// request open indefinitely.
const crawlTimeout = 120 * time.Second

// maxScanTargets caps how many targets one scan job will accept so a huge
// discovered set cannot tie up the server.
const maxScanTargets = 500

// CrawlAPI crawls a seed URL on its own host and statically analyses its JS to
// discover the scan surface (POST { "url": ..., "depth": N, "max_pages": N,
// "cookie": "..." }). It is an active operation: it fetches pages and scripts
// from the target.
func (m *Repository) CrawlAPI(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL      string `json:"url"`
		Depth    int    `json:"depth"`
		MaxPages int    `json:"max_pages"`
		Cookie   string `json:"cookie"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		m.writeAPIError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), crawlTimeout)
	defer cancel()

	result, err := crawl.Crawl(ctx, req.URL, crawl.Options{
		MaxDepth: req.Depth,
		MaxPages: req.MaxPages,
		Cookie:   req.Cookie,
	})
	if err != nil {
		m.writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	m.writeJSON(w, result)
}

// scanOptionsReq is the JSON projection of xss.Options the UI posts.
type scanOptionsReq struct {
	Cookie          string   `json:"cookie"`
	Headers         []string `json:"headers"`
	UserAgent       string   `json:"user_agent"`
	Method          string   `json:"method"`
	SkipMining      bool     `json:"skip_mining"`
	SkipMiningDict  bool     `json:"skip_mining_dict"`
	SkipMiningDOM   bool     `json:"skip_mining_dom"`
	SkipAST         bool     `json:"skip_ast"`
	OnlyPoC         string   `json:"only_poc"`
	BlindURL        string   `json:"blind_url"`
	RateLimit       int      `json:"rate_limit"`
	FollowRedirects bool     `json:"follow_redirects"`
	DeepScan        bool     `json:"deep_scan"`
	WAFEvasion      bool     `json:"waf_evasion"`
	StoredXSS       bool     `json:"stored_xss"`
	SXSSURL         string   `json:"sxss_url"`
	Workers         int      `json:"workers"`
	TimeoutSecs     int      `json:"timeout"`
	DelayMillis     int      `json:"delay"`
	ScanTimeoutSecs int      `json:"scan_timeout"`
}

func (o scanOptionsReq) toXSS() xss.Options {
	return xss.Options{
		Cookie:          o.Cookie,
		Headers:         o.Headers,
		UserAgent:       o.UserAgent,
		Method:          o.Method,
		SkipMining:      o.SkipMining,
		SkipMiningDict:  o.SkipMiningDict,
		SkipMiningDOM:   o.SkipMiningDOM,
		SkipAST:         o.SkipAST,
		OnlyPoC:         o.OnlyPoC,
		BlindURL:        o.BlindURL,
		RateLimit:       o.RateLimit,
		FollowRedirects: o.FollowRedirects,
		DeepScan:        o.DeepScan,
		WAFEvasion:      o.WAFEvasion,
		StoredXSS:       o.StoredXSS,
		SXSSURL:         o.SXSSURL,
		Workers:         o.Workers,
		TimeoutSecs:     o.TimeoutSecs,
		DelayMillis:     o.DelayMillis,
		ScanTimeoutSecs: o.ScanTimeoutSecs,
	}
}

// TargetAPI returns a seed URL for the XSS crawler, derived from the domain and
// scheme Bruter was started with (the -domain CLI flag), so the UI can
// pre-fill the crawl input instead of making the user re-type the target.
func (m *Repository) TargetAPI(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(m.App.Domain)
	seed := domain
	if domain != "" && !strings.Contains(domain, "://") {
		scheme := m.App.Scheme
		if scheme == "" {
			scheme = "https"
		}
		seed = scheme + "://" + domain + "/"
	}
	m.writeJSON(w, map[string]string{"domain": domain, "scheme": m.App.Scheme, "url": seed})
}

// ScanStartAPI launches a background scan job over a list of targets with the
// supplied dalfox options (POST { "targets": [...], "options": {...} }). It
// returns { "job_id": "..." }. When dalfox is not installed it responds 501
// (matching XSSAPI) rather than starting a doomed job.
func (m *Repository) ScanStartAPI(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Targets []string       `json:"targets"`
		Options scanOptionsReq `json:"options"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		m.writeAPIError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if len(req.Targets) == 0 {
		m.writeAPIError(w, http.StatusBadRequest, "at least one target is required")
		return
	}
	if len(req.Targets) > maxScanTargets {
		req.Targets = req.Targets[:maxScanTargets]
	}
	if !xss.Installed() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"error":            xss.ErrNotInstalled.Error(),
			"dalfox_installed": false,
		}); err != nil {
			m.App.ZeroLog.Error().Err(err).Msg("failed to encode scan error response")
		}
		return
	}

	job := m.Scans.Start(req.Targets, req.Options.toXSS(), 0)
	m.writeJSON(w, map[string]string{"job_id": job.ID()})
}

// ScanStatusAPI returns a snapshot of a scan job (GET /api/scan/{id}) — state,
// progress and findings — for the UI to poll.
func (m *Repository) ScanStatusAPI(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	job, ok := m.Scans.Get(id)
	if !ok {
		m.writeAPIError(w, http.StatusNotFound, "no such scan job")
		return
	}
	m.writeJSON(w, job.Snapshot())
}

// ScanStopAPI cancels a running scan job (POST /api/scan/{id}/stop).
func (m *Repository) ScanStopAPI(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !m.Scans.Stop(id) {
		m.writeAPIError(w, http.StatusNotFound, "no such scan job")
		return
	}
	m.writeJSON(w, map[string]bool{"stopped": true})
}

package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"time"
)

// RobtexBaseURL is Robtex's free API. It is a variable so tests can point it at
// a mock server.
var RobtexBaseURL = "https://freeapi.robtex.com"

// robtexNameCap bounds how many passive/active DNS names are returned, since a
// busy (e.g. CDN) IP can map to many thousands of names.
const robtexNameCap = 500

// RobtexName is a single host name associated with an IP and the Unix time (in
// seconds) Robtex last observed the association. For passive-DNS entries this
// dates the observation, which helps tell live records from stale ones.
type RobtexName struct {
	Host string `json:"host"`
	Time int64  `json:"time"`
}

// RobtexIPInfo is the subset of Robtex's ipquery response we surface: network
// ownership (ASN / route / whois) plus active and passive DNS associations.
type RobtexIPInfo struct {
	IP        string       `json:"ip"`
	ASN       int          `json:"asn"`
	ASName    string       `json:"asname"`
	ASDesc    string       `json:"asdesc"`
	BGPRoute  string       `json:"bgproute"`
	WhoisDesc string       `json:"whoisdesc"`
	RouteDesc string       `json:"routedesc"`
	Country   string       `json:"country"`
	City      string       `json:"city"`
	Active    []RobtexName `json:"active"`
	Passive   []RobtexName `json:"passive"`
}

// robtexResponse mirrors the raw ipquery JSON. Robtex reports success/failure
// in a "status" field rather than via HTTP status, and nests DNS associations
// under "act"/"pas" with {o: host, t: time} entries.
type robtexResponse struct {
	Status    string `json:"status"`
	AS        int    `json:"as"`
	ASName    string `json:"asname"`
	ASDesc    string `json:"asdesc"`
	BGPRoute  string `json:"bgproute"`
	WhoisDesc string `json:"whoisdesc"`
	RouteDesc string `json:"routedesc"`
	Country   string `json:"country"`
	City      string `json:"city"`
	Act       []struct {
		O string `json:"o"`
		T int64  `json:"t"`
	} `json:"act"`
	Pas []struct {
		O string `json:"o"`
		T int64  `json:"t"`
	} `json:"pas"`
}

// RobtexIPQuery fetches Robtex's comprehensive view of an IP: network ownership
// and the active/passive DNS names associated with it. Passive DNS in
// particular can reveal host names not visible from a live reverse lookup. It
// is best-effort against a free, rate-limited source and returns an error when
// the source reports a non-ok status or is unreachable.
func RobtexIPQuery(ctx context.Context, ip string) (*RobtexIPInfo, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("invalid IP address %q", ip)
	}
	url := fmt.Sprintf("%s/ipquery/%s", RobtexBaseURL, ip)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", reverseIPUserAgent)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("robtex request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("robtex lookup returned HTTP %d", resp.StatusCode)
	}

	var raw robtexResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("robtex response decode failed: %w", err)
	}
	// An empty status is tolerated (some responses omit it); any explicit
	// non-ok value is an error (e.g. rate limiting).
	if raw.Status != "" && raw.Status != "ok" {
		return nil, fmt.Errorf("robtex source unavailable: status %q", raw.Status)
	}

	info := &RobtexIPInfo{
		IP:        ip,
		ASN:       raw.AS,
		ASName:    raw.ASName,
		ASDesc:    raw.ASDesc,
		BGPRoute:  raw.BGPRoute,
		WhoisDesc: raw.WhoisDesc,
		RouteDesc: raw.RouteDesc,
		Country:   raw.Country,
		City:      raw.City,
		Active:    []RobtexName{},
		Passive:   []RobtexName{},
	}
	for _, a := range raw.Act {
		if len(info.Active) >= robtexNameCap {
			break
		}
		if a.O != "" {
			info.Active = append(info.Active, RobtexName{Host: a.O, Time: a.T})
		}
	}
	for _, p := range raw.Pas {
		if len(info.Passive) >= robtexNameCap {
			break
		}
		if p.O != "" {
			info.Passive = append(info.Passive, RobtexName{Host: p.O, Time: p.T})
		}
	}
	// Sort newest-observation first so the freshest associations lead.
	sort.SliceStable(info.Active, func(i, j int) bool { return info.Active[i].Time > info.Active[j].Time })
	sort.SliceStable(info.Passive, func(i, j int) bool { return info.Passive[i].Time > info.Passive[j].Time })
	return info, nil
}

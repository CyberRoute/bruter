package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/CyberRoute/bruter/pkg/models"
	"github.com/CyberRoute/bruter/pkg/network"
	"github.com/CyberRoute/bruter/pkg/ssl"
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

// WhoisAPI serves the raw WHOIS record as JSON ({ "whois": "..." }).
func (m *Repository) WhoisAPI(w http.ResponseWriter, r *http.Request) {
	whoisInfo, err := network.WhoisLookupRaw(m.App.Domain)
	if err != nil {
		m.checkError(err)
	}
	m.writeJSON(w, map[string]string{"whois": whoisInfo})
}

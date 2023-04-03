package network

import (
	"fmt"
	"net"
)

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

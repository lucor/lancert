// Package privateip provides RFC 1918 private IPv4 address validation,
// parsing, and formatting for the lancert.dev subdomain scheme
// (e.g. 192.168.1.50 <-> "192-168-1-50").
package privateip

import (
	"fmt"
	"net/netip"
	"strings"
)

// RFC 1918 private address ranges.
var rfc1918Ranges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// ParseSubdomain extracts a private IPv4 address from a dashed subdomain
// label such as "192-168-1-50". Returns the parsed address or an error
// if the format is invalid or the IP is not RFC 1918.
func ParseSubdomain(label string) (netip.Addr, error) {
	ipStr := strings.ReplaceAll(label, "-", ".")
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP subdomain %q: %w", label, err)
	}

	if !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("only IPv4 is supported: %s", addr)
	}

	if !IsRFC1918(addr) {
		return netip.Addr{}, fmt.Errorf("IP %s is not a private RFC 1918 address", addr)
	}

	return addr, nil
}

// FormatSubdomain converts a netip.Addr to the dashed subdomain form
// used in lancert.dev domains, e.g. 192.168.1.50 -> "192-168-1-50".
func FormatSubdomain(addr netip.Addr) string {
	return strings.ReplaceAll(addr.String(), ".", "-")
}

// ValidateRFC1918 parses the string as an IP and verifies it belongs to
// one of the three RFC 1918 private ranges. Loopback, link-local, and
// CGNAT addresses are rejected.
func ValidateRFC1918(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP address %q: %w", s, err)
	}

	if !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("only IPv4 is supported: %s", addr)
	}

	if addr.IsLoopback() {
		return netip.Addr{}, fmt.Errorf("loopback address %s is not allowed", addr)
	}

	if !IsRFC1918(addr) {
		return netip.Addr{}, fmt.Errorf("IP %s is not a private RFC 1918 address (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)", addr)
	}

	return addr, nil
}

// IsRFC1918 reports whether addr falls within one of the three RFC 1918
// private address ranges.
func IsRFC1918(addr netip.Addr) bool {
	for _, prefix := range rfc1918Ranges {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Domains returns the two SANs for the given IP: the bare subdomain and
// the wildcard. Example for 192.168.1.50:
//
//	["192-168-1-50.lancert.dev", "*.192-168-1-50.lancert.dev"]
func Domains(addr netip.Addr, zone string) [2]string {
	sub := FormatSubdomain(addr)
	base := sub + "." + zone
	return [2]string{base, "*." + base}
}

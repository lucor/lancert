// Package privateip provides RFC 1918 private IPv4 address validation.
package privateip

import (
	"fmt"
	"net/netip"
)

// RFC 1918 private address ranges.
var rfc1918Ranges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
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

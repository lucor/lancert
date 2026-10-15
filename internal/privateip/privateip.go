// Package privateip provides private IPv4 and IPv6 address validation.
package privateip

import (
	"fmt"
	"net/netip"
)

// Private address ranges supported by Lancert.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fd00::/8"),
}

// Validate parses an IP address and verifies it belongs to an RFC 1918 IPv4
// range or the locally assigned ULA range. Zoned addresses are not supported.
func Validate(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP address %q: %w", s, err)
	}

	if addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("zoned IP address %q is not supported", s)
	}

	if !IsPrivate(addr) {
		return netip.Addr{}, fmt.Errorf("IP %s is not a supported private address (RFC 1918 IPv4 or fd00::/8 ULA)", addr)
	}

	return addr, nil
}

// IsPrivate reports whether addr belongs to a supported RFC 1918 IPv4 range
// or the locally assigned ULA range.
func IsPrivate(addr netip.Addr) bool {
	if !addr.IsValid() {
		// Invalid addresses cannot belong to a supported private range.
		return false
	}
	if addr.Zone() != "" {
		// Zone identifiers are interface-scoped and are not part of DNS addresses.
		return false
	}
	if addr.Is4In6() {
		// Keep IPv4-mapped IPv6 addresses from creating a second form of an IPv4 target.
		return false
	}
	for _, prefix := range privateRanges {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

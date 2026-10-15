package registration

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"time"
)

// DailyUsage reports successful registrations and newly requested private IPs.
type DailyUsage struct {
	Date       string
	Hostnames  uint64
	PrivateIPs uint64
}

// NetworkUsage reports registrations within a private network range.
type NetworkUsage struct {
	Network    string
	Hostnames  uint64
	PrivateIPs uint64
}

// PrivateIPUsage reports registrations for one private IP address.
type PrivateIPUsage struct {
	IP                  string
	Hostnames           uint64
	ACMEActiveHostnames uint64
}

// Usage is an all-time view of how registered hostnames are used.
type Usage struct {
	Hostnames           uint64
	PrivateIPs          uint64
	ACMEActiveHostnames uint64
	Since               time.Time
	Daily               []DailyUsage
	Blocks              []NetworkUsage
	IPv6Blocks          []NetworkUsage
	Prefixes            []NetworkUsage
	IPv6Prefixes        []NetworkUsage
	IPs                 []PrivateIPUsage
	IPv6IPs             []PrivateIPUsage
	RegistrationTargets map[string]string
}

type networkCounter struct {
	hostnames uint64
	ips       map[string]struct{}
}

var privateBlocks = [...]netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

var privateIPv6Block = netip.MustParsePrefix("fd00::/8")

// UsageStats derives public aggregate usage statistics from registration state.
func (s *Store) UsageStats(ctx context.Context) (Usage, error) {
	operationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	rows, err := s.db.QueryContext(operationCtx, `SELECT id,target_ip,challenge_count,created_at FROM registrations ORDER BY created_at,id`)
	if err != nil {
		return Usage{}, fmt.Errorf("registration: query usage: %w", err)
	}
	defer rows.Close()

	daily := make(map[string]*DailyUsage)
	blocks := map[string]*networkCounter{
		"10.0.0.0/8":              {ips: make(map[string]struct{})},
		"172.16.0.0/12":           {ips: make(map[string]struct{})},
		"192.168.0.0/16":          {ips: make(map[string]struct{})},
		privateIPv6Block.String(): {ips: make(map[string]struct{})},
	}
	prefixes := make(map[string]*networkCounter)
	ipv6Prefixes := make(map[string]*networkCounter)
	ips := make(map[string]*PrivateIPUsage)
	ipv6IPs := make(map[string]*PrivateIPUsage)
	seenIPs := make(map[string]struct{})
	usage := Usage{RegistrationTargets: make(map[string]string)}
	for rows.Next() {
		var id, targetIP string
		var challengeCount, createdAt int64
		if err := rows.Scan(&id, &targetIP, &challengeCount, &createdAt); err != nil {
			return Usage{}, fmt.Errorf("registration: scan usage: %w", err)
		}
		addr, err := netip.ParseAddr(targetIP)
		if err != nil {
			return Usage{}, fmt.Errorf("registration: parse usage address %q: %w", targetIP, err)
		}

		usage.Hostnames++
		if usage.Since.IsZero() {
			usage.Since = time.Unix(createdAt, 0).UTC()
		}
		canonicalIP := addr.String()
		usage.RegistrationTargets[id] = canonicalIP
		if challengeCount > 0 {
			usage.ACMEActiveHostnames++
		}
		date := time.Unix(createdAt, 0).UTC().Format("2006-01-02")
		if daily[date] == nil {
			daily[date] = &DailyUsage{Date: date}
		}
		daily[date].Hostnames++
		if _, exists := seenIPs[canonicalIP]; !exists {
			seenIPs[canonicalIP] = struct{}{}
			usage.PrivateIPs++
			daily[date].PrivateIPs++
		}

		block := privateBlock(addr)
		counter := blocks[block]
		if counter == nil {
			return Usage{}, fmt.Errorf("registration: usage address %q is not private", targetIP)
		}
		counter.hostnames++
		counter.ips[canonicalIP] = struct{}{}
		prefixBits := 24
		if addr.Is6() {
			prefixBits = 64
		}
		prefix := netip.PrefixFrom(addr, prefixBits).Masked().String()
		familyPrefixes := prefixes
		familyIPs := ips
		if addr.Is6() {
			familyPrefixes = ipv6Prefixes
			familyIPs = ipv6IPs
		}
		if familyPrefixes[prefix] == nil {
			familyPrefixes[prefix] = &networkCounter{ips: make(map[string]struct{})}
		}
		familyPrefixes[prefix].hostnames++
		familyPrefixes[prefix].ips[canonicalIP] = struct{}{}
		if familyIPs[canonicalIP] == nil {
			familyIPs[canonicalIP] = &PrivateIPUsage{IP: canonicalIP}
		}
		familyIPs[canonicalIP].Hostnames++
		if challengeCount > 0 {
			familyIPs[canonicalIP].ACMEActiveHostnames++
		}
	}
	if err := rows.Err(); err != nil {
		return Usage{}, fmt.Errorf("registration: read usage: %w", err)
	}

	for _, item := range daily {
		usage.Daily = append(usage.Daily, *item)
	}
	sort.Slice(usage.Daily, func(i, j int) bool { return usage.Daily[i].Date < usage.Daily[j].Date })
	for _, network := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		counter := blocks[network]
		usage.Blocks = append(usage.Blocks, NetworkUsage{Network: network, Hostnames: counter.hostnames, PrivateIPs: uint64(len(counter.ips))})
	}
	counter := blocks[privateIPv6Block.String()]
	usage.IPv6Blocks = append(usage.IPv6Blocks, NetworkUsage{Network: privateIPv6Block.String(), Hostnames: counter.hostnames, PrivateIPs: uint64(len(counter.ips))})
	usage.Prefixes = sortedNetworkUsage(prefixes)
	usage.IPv6Prefixes = sortedNetworkUsage(ipv6Prefixes)
	usage.IPs = sortedIPUsage(ips)
	usage.IPv6IPs = sortedIPUsage(ipv6IPs)
	return usage, nil
}

func sortedNetworkUsage(prefixes map[string]*networkCounter) []NetworkUsage {
	usage := make([]NetworkUsage, 0, len(prefixes))
	for network, counter := range prefixes {
		usage = append(usage, NetworkUsage{Network: network, Hostnames: counter.hostnames, PrivateIPs: uint64(len(counter.ips))})
	}
	sort.Slice(usage, func(i, j int) bool {
		if usage[i].Hostnames != usage[j].Hostnames {
			return usage[i].Hostnames > usage[j].Hostnames
		}
		return usage[i].Network < usage[j].Network
	})
	return usage
}

func sortedIPUsage(ips map[string]*PrivateIPUsage) []PrivateIPUsage {
	usage := make([]PrivateIPUsage, 0, len(ips))
	for _, item := range ips {
		usage = append(usage, *item)
	}
	sort.Slice(usage, func(i, j int) bool { return privateIPUsageLess(usage[i], usage[j]) })
	return usage
}

func privateIPUsageLess(left, right PrivateIPUsage) bool {
	if left.Hostnames != right.Hostnames {
		return left.Hostnames > right.Hostnames
	}
	return left.IP < right.IP
}

// CertificateRegistration is the public hostname needed to
// associate a CT certificate with the registration lifecycle.
type CertificateRegistration struct {
	Hostname string
}

// CertificateRegistrations returns active registrations for matching CT names.
// It excludes target addresses and API credentials by construction.
func (s *Store) CertificateRegistrations(ctx context.Context) ([]CertificateRegistration, error) {
	operationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	rows, err := s.db.QueryContext(operationCtx, `SELECT hostname FROM registrations WHERE status='active' ORDER BY hostname`)
	if err != nil {
		return nil, fmt.Errorf("registration: query certificate hostnames: %w", err)
	}
	defer rows.Close()
	var registrations []CertificateRegistration
	for rows.Next() {
		var registration CertificateRegistration
		if err := rows.Scan(&registration.Hostname); err != nil {
			return nil, fmt.Errorf("registration: scan certificate hostname: %w", err)
		}
		registrations = append(registrations, registration)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("registration: read certificate hostnames: %w", err)
	}
	return registrations, nil
}

func privateBlock(addr netip.Addr) string {
	if privateIPv6Block.Contains(addr) {
		return privateIPv6Block.String()
	}
	for _, block := range privateBlocks {
		if block.Contains(addr) {
			return block.String()
		}
	}
	return ""
}

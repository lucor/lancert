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

// PrivateIPUsage reports registrations for one private IPv4 address.
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
	Prefixes            []NetworkUsage
	IPs                 []PrivateIPUsage
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
		"10.0.0.0/8":     {ips: make(map[string]struct{})},
		"172.16.0.0/12":  {ips: make(map[string]struct{})},
		"192.168.0.0/16": {ips: make(map[string]struct{})},
	}
	prefixes := make(map[string]*networkCounter)
	ips := make(map[string]*PrivateIPUsage)
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
		usage.RegistrationTargets[id] = targetIP
		if challengeCount > 0 {
			usage.ACMEActiveHostnames++
		}
		date := time.Unix(createdAt, 0).UTC().Format("2006-01-02")
		if daily[date] == nil {
			daily[date] = &DailyUsage{Date: date}
		}
		daily[date].Hostnames++
		if _, exists := seenIPs[targetIP]; !exists {
			seenIPs[targetIP] = struct{}{}
			usage.PrivateIPs++
			daily[date].PrivateIPs++
		}

		block := privateBlock(addr)
		counter := blocks[block]
		if counter == nil {
			return Usage{}, fmt.Errorf("registration: usage address %q is not private", targetIP)
		}
		counter.hostnames++
		counter.ips[targetIP] = struct{}{}
		prefix := netip.PrefixFrom(addr, 24).Masked().String()
		if prefixes[prefix] == nil {
			prefixes[prefix] = &networkCounter{ips: make(map[string]struct{})}
		}
		prefixes[prefix].hostnames++
		prefixes[prefix].ips[targetIP] = struct{}{}
		if ips[targetIP] == nil {
			ips[targetIP] = &PrivateIPUsage{IP: targetIP}
		}
		ips[targetIP].Hostnames++
		if challengeCount > 0 {
			ips[targetIP].ACMEActiveHostnames++
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
	for network, counter := range prefixes {
		usage.Prefixes = append(usage.Prefixes, NetworkUsage{Network: network, Hostnames: counter.hostnames, PrivateIPs: uint64(len(counter.ips))})
	}
	sort.Slice(usage.Prefixes, func(i, j int) bool {
		if usage.Prefixes[i].Hostnames != usage.Prefixes[j].Hostnames {
			return usage.Prefixes[i].Hostnames > usage.Prefixes[j].Hostnames
		}
		return usage.Prefixes[i].Network < usage.Prefixes[j].Network
	})
	for _, item := range ips {
		usage.IPs = append(usage.IPs, *item)
	}
	sort.Slice(usage.IPs, func(i, j int) bool {
		if usage.IPs[i].Hostnames != usage.IPs[j].Hostnames {
			return usage.IPs[i].Hostnames > usage.IPs[j].Hostnames
		}
		return usage.IPs[i].IP < usage.IPs[j].IP
	})
	return usage, nil
}

func privateBlock(addr netip.Addr) string {
	for _, block := range privateBlocks {
		if block.Contains(addr) {
			return block.String()
		}
	}
	return ""
}

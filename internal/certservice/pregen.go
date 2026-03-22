package certservice

import (
	"context"
	"log/slog"
	"net/netip"
	"time"
)

// PregenIPs is the curated list of private IPs to pre-generate certificates
// for at startup. Covers common gateways, DHCP ranges, homelab defaults,
// and Docker bridge. Limited to 24 to stay well within LE's 50/week limit.
var PregenIPs = []netip.Addr{
	// Common gateways / vendor defaults
	netip.MustParseAddr("192.168.0.1"),
	netip.MustParseAddr("192.168.1.1"),
	netip.MustParseAddr("10.0.0.1"),
	netip.MustParseAddr("10.0.1.1"),
	netip.MustParseAddr("172.17.0.1"),   // Docker default bridge
	netip.MustParseAddr("192.168.0.254"),
	netip.MustParseAddr("192.168.1.254"),
	netip.MustParseAddr("192.168.50.1"),
	netip.MustParseAddr("192.168.88.1"), // MikroTik default

	// Common static/dev host IPs — 192.168.0.x
	netip.MustParseAddr("192.168.0.2"),
	netip.MustParseAddr("192.168.0.9"),
	netip.MustParseAddr("192.168.0.10"),
	netip.MustParseAddr("192.168.0.20"),
	netip.MustParseAddr("192.168.0.50"),
	netip.MustParseAddr("192.168.0.100"),

	// Common static/dev host IPs — 192.168.1.x
	netip.MustParseAddr("192.168.1.2"),
	netip.MustParseAddr("192.168.1.10"),
	netip.MustParseAddr("192.168.1.20"),
	netip.MustParseAddr("192.168.1.50"),
	netip.MustParseAddr("192.168.1.100"),

	// Common static/dev host IPs — 10.0.0.x
	netip.MustParseAddr("10.0.0.10"),
	netip.MustParseAddr("10.0.0.50"),
	netip.MustParseAddr("10.0.0.100"),
	netip.MustParseAddr("10.0.1.10"),
}

// pregenDelay is the pause between consecutive issuance requests during
// pre-generation, to avoid hammering LE.
const pregenDelay = 10 * time.Second

// Pregen issues certificates for all IPs in PregenIPs that are not already
// cached. Runs sequentially with a delay between each issuance. Logs
// progress but does not return errors — individual failures are skipped.
// Meant to be called in a goroutine at startup.
func (s *Service) Pregen(ctx context.Context) {
	total := len(PregenIPs)
	issued := 0
	skipped := 0

	slog.Info("pregen: starting", "total", total)

	for i, addr := range PregenIPs {
		if ctx.Err() != nil {
			slog.Info("pregen: interrupted", "progress", i, "total", total, "issued", issued, "skipped", skipped)
			return
		}

		// Check if already cached
		bundle, err := s.store.Load(addr)
		if err != nil {
			slog.Error("pregen: error loading cert", "addr", addr, "error", err)
			continue
		}

		if bundle != nil && time.Until(bundle.Meta.NotAfter) > renewThreshold {
			skipped++
			continue
		}

		slog.Info("pregen: issuing", "progress", i+1, "total", total, "addr", addr)

		_, err = s.GetOrIssue(ctx, addr)
		if err != nil {
			slog.Error("pregen: failed", "addr", addr, "error", err)
			continue
		}

		issued++

		// Delay between issuances to be gentle with LE
		if i < total-1 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(pregenDelay):
			}
		}
	}

	slog.Info("pregen: complete", "issued", issued, "skipped", skipped, "failed", total-issued-skipped)
}

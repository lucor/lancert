package main

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"lucor.dev/lancert/internal/certservice"
	"lucor.dev/lancert/internal/certstore"
)

func TestReadinessFromInventoryCountsUnexpiredCertificates(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	entries := []certstore.InventoryEntry{
		{Name: "192-168-1-10", Addr: netip.MustParseAddr("192.168.1.10"), Ready: true, Meta: certstore.Meta{IssuedAt: now.Add(-48 * time.Hour), NotAfter: now.Add(certservice.RenewalWindow + time.Hour)}},
		{Name: "192-168-1-11", Addr: netip.MustParseAddr("192.168.1.11"), Ready: true, Meta: certstore.Meta{IssuedAt: now.Add(-24 * time.Hour), NotAfter: now.Add(certservice.RenewalWindow - time.Hour)}},
		{Name: "192-168-1-12", Addr: netip.MustParseAddr("192.168.1.12"), Err: errors.New("missing private key")},
		{Name: "not-an-ip", Err: errors.New("invalid directory")},
	}

	got := readinessFromInventory(entries, now)
	require.True(t, got.Available)
	require.True(t, got.Degraded)
	require.Equal(t, uint64(3), got.Total)
	require.Equal(t, uint64(2), got.Ready)
	require.Contains(t, got.Error, "192-168-1-12")
	issued, since := certificateLifecycleBaseline(entries)
	require.Equal(t, uint64(2), issued)
	require.Equal(t, now.Add(-48*time.Hour), since)
}

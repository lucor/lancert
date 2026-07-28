package main

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"lucor.dev/lancert/internal/certservice"
	"lucor.dev/lancert/internal/certstore"
	"lucor.dev/lancert/internal/dnssrv"
)

func TestParseStaticTXT(t *testing.T) {
	records, err := parseStaticTXT(`{
		"@": {"values": ["verification-a", "verification-b"]},
		"_service": {"ttl": 3600, "values": ["verification-c"]},
		"host.lancert.dev.": {"values": ["verification-fqdn"]}
	}`, "lancert.dev.")
	require.NoError(t, err)
	assert.Equal(t, dnssrv.StaticTXTRecord{
		TTL:    defaultStaticTXTTTL,
		Values: []string{"verification-a", "verification-b"},
	}, records["lancert.dev."])
	assert.Equal(t, dnssrv.StaticTXTRecord{
		TTL:    3600,
		Values: []string{"verification-c"},
	}, records["_service.lancert.dev."])
	assert.Equal(t, dnssrv.StaticTXTRecord{
		TTL:    defaultStaticTXTTTL,
		Values: []string{"verification-fqdn"},
	}, records["host.lancert.dev."])
}

func TestParseStaticTXTRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "invalid JSON", raw: `{`},
		{name: "empty configuration", raw: `{}`},
		{name: "outside zone", raw: `{"other.example.":{"values":["value"]}}`},
		{name: "reserved ACME name", raw: `{"_acme-challenge.host":{"values":["value"]}}`},
		{name: "missing values", raw: `{"@":{"ttl":300}}`},
		{name: "empty value", raw: `{"@":{"values":[""]}}`},
		{name: "unknown property", raw: `{"@":{"cache":300,"values":["value"]}}`},
		{name: "trailing JSON", raw: `{"@":{"values":["value"]}} {}`},
		{name: "duplicate normalized name", raw: `{"@":{"values":["a"]},"lancert.dev.":{"values":["b"]}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseStaticTXT(tt.raw, "lancert.dev.")
			require.Error(t, err)
		})
	}
}

func TestParseStaticTXTUnset(t *testing.T) {
	records, err := parseStaticTXT("", "lancert.dev.")
	require.NoError(t, err)
	assert.Nil(t, records)
}

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

package dnsconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lucor.dev/lancert/internal/dnssrv"
)

func TestParseStaticTXT(t *testing.T) {
	records, err := ParseStaticTXT(`{
		"@": {"values": ["verification-a", "verification-b"]},
		"_service": {"ttl": 3600, "values": ["verification-c"]},
		"host.lancert.dev.": {"values": ["verification-fqdn"]}
	}`, "lancert.dev.")
	require.NoError(t, err)
	assert.Equal(t, dnssrv.StaticTXTRecord{TTL: defaultStaticTXTTTL, Values: []string{"verification-a", "verification-b"}}, records["lancert.dev."])
	assert.Equal(t, dnssrv.StaticTXTRecord{TTL: 3600, Values: []string{"verification-c"}}, records["_service.lancert.dev."])
	assert.Equal(t, dnssrv.StaticTXTRecord{TTL: defaultStaticTXTTTL, Values: []string{"verification-fqdn"}}, records["host.lancert.dev."])
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
			_, err := ParseStaticTXT(tt.raw, "lancert.dev.")
			require.Error(t, err)
		})
	}
}

func TestParseStaticTXTUnset(t *testing.T) {
	records, err := ParseStaticTXT("", "lancert.dev.")
	require.NoError(t, err)
	assert.Nil(t, records)
}

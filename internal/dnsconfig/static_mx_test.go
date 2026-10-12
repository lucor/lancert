package dnsconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lucor.dev/lancert/internal/dnssrv"
)

func TestParseStaticMX(t *testing.T) {
	records, err := ParseStaticMX(`{
		"@": {"records": [{"preference": 10, "exchange": " MX1.EXAMPLE.NET "}, {"preference": 20, "exchange": "mx2.example.net."}]},
		"mail": {"ttl": 3600, "records": [{"preference": 0, "exchange": "mail.example.net"}]},
		"host.lancert.dev.": {"ttl": 0, "records": [{"preference": 0, "exchange": "."}]}
	}`, "LANCERT.DEV.")
	require.NoError(t, err)
	assert.Equal(t, dnssrv.StaticMXRecord{TTL: defaultStaticMXTTL, Records: []dnssrv.MXRecord{
		{Preference: 10, Exchange: "mx1.example.net."},
		{Preference: 20, Exchange: "mx2.example.net."},
	}}, records["lancert.dev."])
	assert.Equal(t, dnssrv.StaticMXRecord{TTL: 3600, Records: []dnssrv.MXRecord{{Exchange: "mail.example.net."}}}, records["mail.lancert.dev."])
	assert.Equal(t, dnssrv.StaticMXRecord{Records: []dnssrv.MXRecord{{Exchange: "."}}}, records["host.lancert.dev."])
}

func TestParseStaticMXRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "invalid JSON", raw: `{`},
		{name: "empty configuration", raw: `{}`},
		{name: "null configuration", raw: `null`},
		{name: "empty name", raw: `{"":{"records":[{"exchange":"mx.example.net"}]}}`},
		{name: "outside zone", raw: `{"other.example.":{"records":[{"exchange":"mx.example.net"}]}}`},
		{name: "reserved ACME name", raw: `{"_acme-challenge.host":{"records":[{"exchange":"mx.example.net"}]}}`},
		{name: "missing records", raw: `{"@":{"ttl":300}}`},
		{name: "empty exchange", raw: `{"@":{"records":[{"preference":10}]}}`},
		{name: "invalid exchange", raw: `{"@":{"records":[{"exchange":"mx..example.net"}]}}`},
		{name: "IP exchange", raw: `{"@":{"records":[{"exchange":"192.0.2.1"}]}}`},
		{name: "wildcard exchange", raw: `{"@":{"records":[{"exchange":"*.example.net"}]}}`},
		{name: "negative preference", raw: `{"@":{"records":[{"preference":-1,"exchange":"mx.example.net"}]}}`},
		{name: "oversized preference", raw: `{"@":{"records":[{"preference":65536,"exchange":"mx.example.net"}]}}`},
		{name: "unknown property", raw: `{"@":{"records":[{"priority":10,"exchange":"mx.example.net"}]}}`},
		{name: "trailing JSON", raw: `{"@":{"records":[{"exchange":"mx.example.net"}]}} {}`},
		{name: "duplicate normalized name", raw: `{"@":{"records":[{"exchange":"mx.example.net"}]},"lancert.dev.":{"records":[{"exchange":"mx.example.net"}]}}`},
		{name: "null MX preference", raw: `{"@":{"records":[{"preference":10,"exchange":"."}]}}`},
		{name: "null MX with mail server", raw: `{"@":{"records":[{"exchange":"."},{"exchange":"mx.example.net"}]}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseStaticMX(tt.raw, "lancert.dev.")
			require.Error(t, err)
		})
	}
}

func TestParseStaticMXUnset(t *testing.T) {
	records, err := ParseStaticMX("", "lancert.dev.")
	require.NoError(t, err)
	assert.Nil(t, records)
}

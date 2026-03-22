package privateip

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSubdomain(t *testing.T) {
	tests := []struct {
		name    string
		label   string
		want    netip.Addr
		wantErr bool
	}{
		{name: "valid 192.168", label: "192-168-1-50", want: netip.MustParseAddr("192.168.1.50")},
		{name: "valid 10.x", label: "10-0-0-1", want: netip.MustParseAddr("10.0.0.1")},
		{name: "valid 172.16", label: "172-16-0-1", want: netip.MustParseAddr("172.16.0.1")},
		{name: "public IP rejected", label: "8-8-8-8", wantErr: true},
		{name: "loopback rejected", label: "127-0-0-1", wantErr: true},
		{name: "invalid format", label: "not-an-ip", wantErr: true},
		{name: "empty", label: "", wantErr: true},
		{name: "CGNAT rejected", label: "100-64-0-1", wantErr: true},
		{name: "link-local rejected", label: "169-254-1-1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSubdomain(tt.label)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFormatSubdomain(t *testing.T) {
	addr := netip.MustParseAddr("192.168.1.50")
	assert.Equal(t, "192-168-1-50", FormatSubdomain(addr))
}

func TestValidateRFC1918(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "10.x valid", input: "10.255.255.255"},
		{name: "172.16 valid", input: "172.16.0.1"},
		{name: "172.31 valid", input: "172.31.255.255"},
		{name: "192.168 valid", input: "192.168.0.1"},
		{name: "172.15 invalid", input: "172.15.0.1", wantErr: true},
		{name: "172.32 invalid", input: "172.32.0.1", wantErr: true},
		{name: "public", input: "1.1.1.1", wantErr: true},
		{name: "loopback", input: "127.0.0.1", wantErr: true},
		{name: "garbage", input: "xyz", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateRFC1918(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDomains(t *testing.T) {
	addr := netip.MustParseAddr("192.168.1.50")
	got := Domains(addr, "lancert.dev")
	assert.Equal(t, [2]string{"192-168-1-50.lancert.dev", "*.192-168-1-50.lancert.dev"}, got)
}

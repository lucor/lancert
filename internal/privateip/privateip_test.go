package privateip

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "10.x valid", input: "10.255.255.255", want: "10.255.255.255"},
		{name: "172.16 valid", input: "172.16.0.1", want: "172.16.0.1"},
		{name: "172.31 valid", input: "172.31.255.255", want: "172.31.255.255"},
		{name: "192.168 valid", input: "192.168.0.1", want: "192.168.0.1"},
		{name: "ULA valid", input: "FD12:3456:789A:0001:0000:0000:0000:0025", want: "fd12:3456:789a:1::25"},
		{name: "ULA compressed", input: "fd12:3456:789a:1::25", want: "fd12:3456:789a:1::25"},
		{name: "172.15 invalid", input: "172.15.0.1", wantErr: true},
		{name: "172.32 invalid", input: "172.32.0.1", wantErr: true},
		{name: "public", input: "1.1.1.1", wantErr: true},
		{name: "loopback", input: "127.0.0.1", wantErr: true},
		{name: "ULA reserved assignment", input: "fc12:3456:789a:1::25", wantErr: true},
		{name: "global IPv6", input: "2001:db8::1", wantErr: true},
		{name: "link-local", input: "fe80::1", wantErr: true},
		{name: "IPv6 loopback", input: "::1", wantErr: true},
		{name: "IPv6 unspecified", input: "::", wantErr: true},
		{name: "multicast", input: "ff02::1", wantErr: true},
		{name: "IPv4 mapped", input: "::ffff:192.168.1.1", wantErr: true},
		{name: "zoned ULA", input: "fd12:3456:789a:1::25%en0", wantErr: true},
		{name: "prefix", input: "fd12:3456:789a:1::/64", wantErr: true},
		{name: "garbage", input: "xyz", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Validate(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got.String())
			}
		})
	}
}

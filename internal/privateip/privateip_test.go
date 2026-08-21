package privateip

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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

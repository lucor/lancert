package api

import (
	"context"
	"net/http"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRealIP_Resolve(t *testing.T) {
	proxySubnet := netip.MustParsePrefix("172.20.0.0/16")

	tests := []struct {
		name       string
		proxy      netip.Prefix
		remoteAddr string
		xff        string
		want       string
	}{
		{
			name:       "direct connection, no proxy configured",
			proxy:      netip.Prefix{},
			remoteAddr: "95.12.34.56:54321",
			want:       "95.12.34.56",
		},
		{
			name:       "direct connection, spoofed XFF ignored",
			proxy:      netip.Prefix{},
			remoteAddr: "95.12.34.56:54321",
			xff:        "1.2.3.4",
			want:       "95.12.34.56",
		},
		{
			name:       "proxy configured, peer in subnet, real client in XFF",
			proxy:      proxySubnet,
			remoteAddr: "172.20.0.2:12345",
			xff:        "95.12.34.56",
			want:       "95.12.34.56",
		},
		{
			name:       "proxy configured, peer in subnet, spoofed leftmost ignored",
			proxy:      proxySubnet,
			remoteAddr: "172.20.0.2:12345",
			xff:        "1.1.1.1, 95.12.34.56",
			want:       "95.12.34.56",
		},
		{
			name:       "proxy configured, peer outside subnet, XFF ignored",
			proxy:      proxySubnet,
			remoteAddr: "203.0.113.5:9999",
			xff:        "1.2.3.4",
			want:       "203.0.113.5",
		},
		{
			name:       "proxy configured, peer in subnet, no XFF, fallback to peer",
			proxy:      proxySubnet,
			remoteAddr: "172.20.0.2:12345",
			want:       "172.20.0.2",
		},
		{
			name:       "proxy configured, IPv6-mapped IPv4 in XFF",
			proxy:      proxySubnet,
			remoteAddr: "172.20.0.2:12345",
			xff:        "::ffff:95.12.34.56",
			want:       "95.12.34.56",
		},
		{
			name:       "proxy configured, invalid XFF, fallback to peer",
			proxy:      proxySubnet,
			remoteAddr: "172.20.0.2:12345",
			xff:        "garbage",
			want:       "172.20.0.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rip := NewRealIP(tt.proxy)
			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     http.Header{},
			}
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			got := rip.Resolve(req)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRealIP_Resolve_MultipleXFFHeaders(t *testing.T) {
	rip := NewRealIP(netip.MustParsePrefix("172.20.0.0/16"))
	req := &http.Request{
		RemoteAddr: "172.20.0.2:12345",
		Header:     http.Header{},
	}
	req.Header.Add("X-Forwarded-For", "1.1.1.1")    // spoofed by attacker
	req.Header.Add("X-Forwarded-For", "95.12.34.56") // appended by proxy

	got := rip.Resolve(req)
	assert.Equal(t, "95.12.34.56", got)
}

func TestClientIPFromContext(t *testing.T) {
	ctx := WithClientIP(context.Background(), "95.12.34.56")
	ip, ok := ClientIPFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, "95.12.34.56", ip)

	_, ok = ClientIPFromContext(context.Background())
	assert.False(t, ok)
}

func TestHashedIPFromContext(t *testing.T) {
	ctx := WithHashedIP(context.Background(), "abc123")
	ip, ok := HashedIPFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, "abc123", ip)

	_, ok = HashedIPFromContext(context.Background())
	assert.False(t, ok)
}

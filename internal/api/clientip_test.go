package api

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveIP(t *testing.T) {
	proxySubnet := netip.MustParsePrefix("172.20.0.0/16")
	noProxy := netip.Prefix{}

	tests := []struct {
		name        string
		proxy       netip.Prefix
		remoteAddr  string
		xff         string
		want        string
	}{
		{
			name:       "direct connection, no proxy configured",
			proxy:      noProxy,
			remoteAddr: "95.12.34.56:54321",
			want:       "95.12.34.56",
		},
		{
			name:       "direct connection, spoofed XFF ignored",
			proxy:      noProxy,
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
			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     http.Header{},
			}
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			got := resolveIP(req, tt.proxy)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestObfuscateIP(t *testing.T) {
	// Deterministic: same input → same output
	a := obfuscateIP("95.12.34.56")
	b := obfuscateIP("95.12.34.56")
	assert.Equal(t, a, b)
	assert.Len(t, a, 16)

	// Different IPs → different hashes
	c := obfuscateIP("10.0.0.1")
	assert.NotEqual(t, a, c)
}

func TestResolveIP_MultipleXFFHeaders(t *testing.T) {
	// Attacker sends a spoofed X-Forwarded-For header; the proxy appends
	// the real client IP as a separate header. We must read the rightmost
	// value across all headers, not just the first one.
	proxySubnet := netip.MustParsePrefix("172.20.0.0/16")
	req := &http.Request{
		RemoteAddr: "172.20.0.2:12345",
		Header:     http.Header{},
	}
	req.Header.Add("X-Forwarded-For", "1.1.1.1")   // spoofed by attacker
	req.Header.Add("X-Forwarded-For", "95.12.34.56") // appended by proxy

	got := resolveIP(req, proxySubnet)
	assert.Equal(t, "95.12.34.56", got)
}

func TestClientIPFrom_Fallback(t *testing.T) {
	// Without middleware, falls back to obfuscated RemoteAddr.
	req := &http.Request{RemoteAddr: "95.12.34.56:54321"}
	got := ClientIPFrom(req)
	want := obfuscateIP("95.12.34.56")
	assert.Equal(t, want, got)
}

func TestClientIPFrom_IPv6MappedConsistency(t *testing.T) {
	// IPv4 and IPv4-mapped IPv6 must produce the same hash.
	r4 := &http.Request{RemoteAddr: "95.12.34.56:1234"}
	r6 := &http.Request{RemoteAddr: "[::ffff:95.12.34.56]:1234"}
	assert.Equal(t, ClientIPFrom(r4), ClientIPFrom(r6))
}

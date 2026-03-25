package api

// Client IP resolution for servers behind a single reverse proxy.
//
// Inspired by github.com/realclientip/realclientip-go — when a trusted
// proxy subnet is configured, X-Forwarded-For is only read if RemoteAddr
// falls within that subnet. The rightmost XFF entry (appended by the
// proxy) is used as the real client IP. All IPs are obfuscated before
// storage.
//
// This implementation supports a single trusted proxy (e.g. Traefik, Nginx),
// which covers the realistic deployment scenarios for lancert. Multi-proxy
// chains would require validating each hop's CIDR — not worth the complexity
// given the expected deployment topology.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type contextKey int

const clientIPKey contextKey = iota

// ClientIP returns a middleware that resolves the real client IP, obfuscates
// it with a one-way hash, and stores the result in the request context.
// proxySubnet is the CIDR of the trusted reverse proxy (e.g. "172.20.0.0/16").
// Pass netip.Prefix{} (zero value) for direct connections with no proxy.
//
// Use the narrowest possible CIDR (ideally /32 for a single proxy IP).
// A wide subnet trusts any peer within it, which in shared networks could
// allow other hosts to spoof X-Forwarded-For.
func ClientIP(proxySubnet netip.Prefix) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := resolveIP(r, proxySubnet)
			ctx := context.WithValue(r.Context(), clientIPKey, obfuscateIP(ip))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClientIPFrom reads the obfuscated client IP from the request context.
// Falls back to obfuscating RemoteAddr if the ClientIP middleware is not
// in the chain (e.g. in tests).
func ClientIPFrom(r *http.Request) string {
	if v, ok := r.Context().Value(clientIPKey).(string); ok {
		return v
	}
	return obfuscateIP(canonicalIP(r.RemoteAddr))
}

// resolveIP extracts the real client IP from the request.
// If proxySubnet is configured and RemoteAddr falls within it, the
// rightmost X-Forwarded-For entry is used. Otherwise RemoteAddr is
// returned directly.
func resolveIP(r *http.Request, proxySubnet netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()

	if !proxySubnet.IsValid() || !proxySubnet.Contains(peer) {
		return peer.String()
	}

	// Join all X-Forwarded-For headers: a proxy may append a separate
	// header rather than extending the existing one. Using only Get()
	// would read the first header, letting an attacker spoof the value.
	xff := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	if ip := rightmostXFF(xff); ip != "" {
		return ip
	}

	return peer.String()
}

// rightmostXFF returns the rightmost valid IP from an X-Forwarded-For
// header value, or "" if the header is empty or unparseable.
// The rightmost entry is the one appended by the trusted proxy.
func rightmostXFF(xff string) string {
	if xff == "" {
		return ""
	}
	raw := xff
	if i := strings.LastIndex(xff, ","); i >= 0 {
		raw = xff[i+1:]
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return addr.Unmap().String()
}

// canonicalIP extracts the IP from a host:port string and normalises
// IPv4-mapped IPv6 addresses so the same client always produces the
// same obfuscated hash.
func canonicalIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	return addr.Unmap().String()
}

// obfuscateIP hashes an IP address so it can be used as a rate-limit key
// and logged without storing plaintext client IPs.
// Returns the first 16 hex characters of the SHA-256 digest.
func obfuscateIP(ip string) string {
	h := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(h[:8])
}

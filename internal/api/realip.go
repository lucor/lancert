package api

// Client IP resolution for servers behind a single reverse proxy.
//
// Inspired by github.com/realclientip/realclientip-go — when a trusted
// proxy subnet is configured, X-Forwarded-For is only read if RemoteAddr
// falls within that subnet. The rightmost XFF entry (appended by the
// proxy) is used as the real client IP.
//
// This implementation supports a single trusted proxy (e.g. Traefik, Nginx),
// which covers the realistic deployment scenarios for lancert. Multi-proxy
// chains would require validating each hop's CIDR — not worth the complexity
// given the expected deployment topology.

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type clientIPCtxKey struct{}

// ClientIPFromContext returns the canonical client IP for the request,
// resolved by RealIP from RemoteAddr or trusted X-Forwarded-For.
func ClientIPFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(clientIPCtxKey{}).(string)
	return v, ok
}

// WithClientIP returns a copy of ctx with the plain client IP stored.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPCtxKey{}, ip)
}

// RealIP resolves the real client IP from RemoteAddr or X-Forwarded-For
// based on a trusted proxy subnet.
type RealIP struct {
	proxySubnet netip.Prefix
}

// NewRealIP creates a RealIP resolver.
// proxySubnet is the CIDR of the trusted reverse proxy (e.g. "172.20.0.0/16").
// Pass netip.Prefix{} (zero value) for direct connections with no proxy.
//
// Use the narrowest possible CIDR (ideally /32 for a single proxy IP).
// A wide subnet trusts any peer within it, which in shared networks could
// allow other hosts to spoof X-Forwarded-For.
func NewRealIP(proxySubnet netip.Prefix) *RealIP {
	return &RealIP{proxySubnet: proxySubnet}
}

// Resolve extracts the real client IP from the request.
// If proxySubnet is configured and RemoteAddr falls within it, the
// rightmost X-Forwarded-For entry is used. Otherwise RemoteAddr is
// returned directly.
func (rip *RealIP) Resolve(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()

	if !rip.proxySubnet.IsValid() || !rip.proxySubnet.Contains(peer) {
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

// Middleware stores the resolved client IP in the request context.
func (rip *RealIP) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := rip.Resolve(r)
		ctx := WithClientIP(r.Context(), ip)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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

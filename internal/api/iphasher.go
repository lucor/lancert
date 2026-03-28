package api

import (
	"context"
	"encoding/hex"
	"log/slog"
	"net/http"

	"golang.org/x/crypto/blake2b"
)

type hashedIPCtxKey struct{}

// HashedIPFromContext reads the hashed client IP stored by the
// IPHasher middleware. Returns the hashed IP and true if present.
func HashedIPFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(hashedIPCtxKey{}).(string)
	return v, ok
}

// WithHashedIP returns a copy of ctx with the hashed client IP stored.
func WithHashedIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, hashedIPCtxKey{}, ip)
}

// IPHasher hashes client IPs with a keyed BLAKE2b so they can be used
// as rate-limit keys and logged without storing plaintext addresses.
type IPHasher struct {
	key [32]byte
}

// NewIPHasher creates an IPHasher. The secret is used as a BLAKE2b key
// to prevent rainbow-table reversal of hashed IPs.
func NewIPHasher(secret string) *IPHasher {
	return &IPHasher{key: blake2b.Sum256([]byte(secret))}
}

// Hash returns a 32 hex-character keyed BLAKE2b hash of the IP.
func (h *IPHasher) Hash(ip string) string {
	bh, _ := blake2b.New(16, h.key[:]) // 16 bytes → 32 hex chars
	bh.Write([]byte(ip))
	return hex.EncodeToString(bh.Sum(nil))
}

// Middleware reads the plain client IP from context, hashes it,
// and stores the result. Requires the ClientIP middleware to run first.
func (h *IPHasher) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, ok := ClientIPFromContext(r.Context())
		if !ok {
			slog.Error("ip hasher: missing client IP in context")
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		ctx := WithHashedIP(r.Context(), h.Hash(ip))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

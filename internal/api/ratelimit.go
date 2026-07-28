package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	// IssuanceRPS is the steady-state rate for certificate issuance.
	// 1 req/s keeps individual clients from hammering the ACME provider
	// while still allowing normal interactive use.
	IssuanceRPS rate.Limit = 1

	// IssuanceBurst is the maximum burst for certificate issuance.
	// 3 lets a client quickly issue certs for a small cluster of IPs
	// (e.g. 10.0.0.1-3) without waiting between each request.
	IssuanceBurst = 3

	// CertificateReadRPS permits the documented 10-second polling interval
	// while preventing a single client from repeatedly downloading certificate
	// material. The shared burst allows an initial status check plus the two
	// PEM downloads without delay.
	CertificateReadRPS rate.Limit = 0.1

	CertificateReadBurst = 3

	// InitialIssuanceBurst lets a new client provision a small local cluster
	// immediately. Only cache misses that actually start issuance consume it.
	InitialIssuanceBurst = 10

	// InitialIssuanceRefill prevents one client from monopolizing the shared
	// certificate authority capacity after its initial provisioning burst.
	InitialIssuanceRefill = 24 * time.Hour
)

// RateLimiter tracks per-key request rates using token buckets.
// Keys are hashed client IPs read from the request context (set by
// IPHasher middleware). Only POST requests are rate-limited; all other
// methods pass through unconditionally.
//
// Idle-entry eviction: entries not seen for idleTTL are removed by a
// background sweep every cleanupEvery.
//
//   - Refill time = burst / rps (time to fully replenish the token bucket).
//   - idleTTL must be >= refill time. Evicting sooner resets
//     the bucket, giving the client a fresh burst and defeating the limit.
//   - Default idleTTL = max(3×refill, 1 min): once the bucket is fully
//     refilled, keeping the entry longer doesn't strengthen rate limiting,
//     it only reduces map churn. 3× gives a comfortable margin.
//   - cleanupEvery = max(idleTTL/3, 10s): balances memory reclaim vs lock
//     contention. Actual eviction is approximate: [idleTTL, idleTTL+cleanupEvery].
type RateLimiter struct {
	mu           sync.Mutex
	entries      map[string]*rateLimiterEntry
	rps          rate.Limit
	burst        int
	idleTTL      time.Duration
	cleanupEvery time.Duration
}

type rateLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter creates a per-key token-bucket limiter.
// rps is the steady-state rate (requests per second); burst is the
// maximum tokens available for short bursts.
// Idle-entry TTL and cleanup interval are derived from rps and burst
// (see type doc). The cleanup goroutine runs until ctx is cancelled.
func NewRateLimiter(ctx context.Context, rps rate.Limit, burst int) *RateLimiter {
	refill := time.Duration(float64(time.Second) * float64(burst) / float64(rps))
	idleTTL := max(3*refill, time.Minute)
	cleanupEvery := max(idleTTL/3, 10*time.Second)

	rl := &RateLimiter{
		entries:      make(map[string]*rateLimiterEntry),
		rps:          rps,
		burst:        burst,
		idleTTL:      idleTTL,
		cleanupEvery: cleanupEvery,
	}
	go rl.cleanup(ctx)
	return rl
}

// NewInitialIssuanceRateLimiter creates the slow per-client limiter for new
// certificate issuance. Cached certificates and existing in-flight issuance
// do not pass through this limiter.
func NewInitialIssuanceRateLimiter(ctx context.Context) *RateLimiter {
	return NewRateLimiter(ctx, rate.Every(InitialIssuanceRefill), InitialIssuanceBurst)
}

// Allow reports whether a request with the given key should be permitted.
func (rl *RateLimiter) Allow(key string) bool {
	allowed, _ := rl.AllowWithRetry(key)
	return allowed
}

// AllowWithRetry reports whether key may proceed and, when denied, how long it
// must wait for the next token. Checking and calculating the delay use the same
// limiter instant so the result is consistent under concurrent requests.
func (rl *RateLimiter) AllowWithRetry(key string) (bool, time.Duration) {
	rl.mu.Lock()
	e, ok := rl.entries[key]
	if !ok {
		e = &rateLimiterEntry{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.entries[key] = e
	}
	now := time.Now()
	e.lastSeen = now
	rl.mu.Unlock()

	if e.limiter.AllowN(now, 1) {
		return true, 0
	}

	reservation := e.limiter.ReserveN(now, 1)
	delay := reservation.DelayFrom(now)
	reservation.CancelAt(now)
	return false, delay
}

// cleanup periodically removes entries idle for longer than idleTTL.
func (rl *RateLimiter) cleanup(ctx context.Context) {
	ticker := time.NewTicker(rl.cleanupEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for key, e := range rl.entries {
				if now.Sub(e.lastSeen) > rl.idleTTL {
					delete(rl.entries, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// Middleware enforces the rate limit on POST requests using the hashed
// client IP from the request context as the bucket key.
// Non-POST requests pass through without rate limiting.
// Requires the IPHasher middleware to run first.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		ip, ok := HashedIPFromContext(r.Context())
		if !ok {
			slog.Error("rate limiter: missing hashed IP in context")
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		if !rl.Allow(ip) {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded, try again later")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// CertificateReadMiddleware limits GET requests below /certs/. It shares one
// bucket across status, TTL, and PEM endpoints for each hashed client IP so a
// caller cannot bypass the limit by alternating endpoint paths.
// Requires the IPHasher middleware to run first.
func (rl *RateLimiter) CertificateReadMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/certs/") {
			next.ServeHTTP(w, r)
			return
		}

		ip, ok := HashedIPFromContext(r.Context())
		if !ok {
			slog.Error("certificate read limiter: missing hashed IP in context")
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		if !rl.Allow(ip) {
			w.Header().Set("Retry-After", "10")
			writeError(w, http.StatusTooManyRequests, "certificate read rate limit exceeded, try again later")
			return
		}

		next.ServeHTTP(w, r)
	})
}

package api

import (
	"context"
	"log/slog"
	"net/http"
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

// Allow reports whether a request with the given key should be permitted.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	e, ok := rl.entries[key]
	if !ok {
		e = &rateLimiterEntry{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.entries[key] = e
	}
	e.lastSeen = time.Now()
	rl.mu.Unlock()

	return e.limiter.Allow()
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

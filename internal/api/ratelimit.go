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
	RegistrationBurst      = 3
	RegistrationRetryAfter = "10"
	UpdateBurst            = 6
	UpdateRetryAfter       = "1"
)

// RateLimiter tracks bounded-lifetime token buckets by privacy-preserving key.
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

// Allow reports whether key may consume one token.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	entry, ok := rl.entries[key]
	if !ok {
		entry = &rateLimiterEntry{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.entries[key] = entry
	}
	now := time.Now()
	entry.lastSeen = now
	rl.mu.Unlock()
	return entry.limiter.AllowN(now, 1)
}

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
			for key, entry := range rl.entries {
				if now.Sub(entry.lastSeen) > rl.idleTTL {
					delete(rl.entries, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// Limits applies one independent per-client-IP bucket to each mutation endpoint.
type Limits struct {
	registration *RateLimiter
	update       *RateLimiter
}

// NewLimits creates the simple first-release policy. Client IPs are exact
// privacy-preserving hashes supplied by IPHasher middleware.
func NewLimits(ctx context.Context) *Limits {
	return &Limits{
		registration: NewRateLimiter(ctx, rate.Limit(1), RegistrationBurst),
		update:       NewRateLimiter(ctx, rate.Limit(1), UpdateBurst),
	}
}

// Middleware applies the matching endpoint policy before request parsing or
// authentication. Both buckets use the exact client IP hash as their key.
func (l *Limits) Middleware(next http.Handler) http.Handler {
	if l == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		clientIP, ok := HashedIPFromContext(r.Context())
		if !ok {
			slog.Error("rate limiter: missing client IP")
			writeError(w, http.StatusInternalServerError, "internal_error")
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/register/"):
			if !l.registration.Allow(clientIP) {
				w.Header().Set("Retry-After", RegistrationRetryAfter)
				writeError(w, http.StatusTooManyRequests, "rate_limited")
				return
			}
		case r.URL.Path == "/update":
			if !l.update.Allow(clientIP) {
				w.Header().Set("Retry-After", UpdateRetryAfter)
				writeError(w, http.StatusTooManyRequests, "rate_limited")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

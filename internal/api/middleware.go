package api

import (
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Middleware wraps an http.Handler.
type Middleware func(http.Handler) http.Handler

// Chain applies middlewares in order (first listed = outermost).
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// RequestLogging logs method, path, status, and duration for API requests.
// Only /certs/ paths are logged — operational endpoints, static pages, and
// bot probes are silenced to reduce noise.
// Reads the obfuscated client IP from the request context (set by ClientIP middleware).
func RequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/certs/") {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(sw, r)

		slog.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration", time.Since(start).Round(time.Millisecond),
			"client_ip", ClientIPFrom(r),
		)
	})
}

// PerIPRateLimit returns a middleware that limits requests per source IP.
// rps is the steady-state rate (requests/second), burst is the burst size.
// The done channel stops the background cleanup goroutine when closed.
func PerIPRateLimit(rps rate.Limit, burst int, done <-chan struct{}) Middleware {
	var (
		mu       sync.Mutex
		limiters = make(map[string]*entry)
	)

	// Periodically clean up stale entries
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				mu.Lock()
				now := time.Now()
				for ip, e := range limiters {
					if now.Sub(e.lastSeen) > 30*time.Minute {
						delete(limiters, ip)
					}
				}
				mu.Unlock()
			}
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := ClientIPFrom(r)

			mu.Lock()
			e, ok := limiters[ip]
			if !ok {
				e = &entry{limiter: rate.NewLimiter(rps, burst)}
				limiters[ip] = e
			}
			e.lastSeen = time.Now()
			mu.Unlock()

			if !e.limiter.Allow() {
				w.Header().Set("Retry-After", "1")
				writeError(w, http.StatusTooManyRequests, "rate limit exceeded, try again later")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GzipResponse compresses responses with gzip when the client accepts it.
// Removes Content-Length since the compressed size differs from the original.
func GzipResponse(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		gz, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		defer gz.Close()

		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")
		w.Header().Del("Content-Length")

		next.ServeHTTP(&gzipWriter{ResponseWriter: w, Writer: gz}, r)
	})
}

type gzipWriter struct {
	http.ResponseWriter
	io.Writer
}

func (w *gzipWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

// SecurityHeaders sets security-related response headers on every response.
// Cache-Control: no-store is critical because API responses may contain private keys.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// Recover catches panics and returns a 500 response.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				slog.Error("http panic", "error", err)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}


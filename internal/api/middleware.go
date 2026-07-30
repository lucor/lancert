package api

import (
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"lucor.dev/lancert/internal/certservice"
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
// Reads the hashed client IP from the request context (set by IPHasher middleware).
func RequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/certs/") {
			next.ServeHTTP(w, r)
			return
		}

		ip, ok := HashedIPFromContext(r.Context())
		if !ok {
			slog.Error("request logging: missing hashed IP in context")
			writeError(w, http.StatusInternalServerError, "internal server error")
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
			"client_ip", ip,
		)
	})
}

const (
	suspensionRetryAfter     = "86400"
	issuanceSuspendedCode    = "certificate_issuance_suspended"
	downloadSuspendedCode    = "certificate_download_suspended"
	issuanceSuspendedMessage = "Certificate issuance is temporarily suspended while Lancert reviews its certificate distribution model."
	downloadSuspendedMessage = "Certificate downloads are temporarily suspended while Lancert reviews its certificate distribution model."
)

// CertificateSuspension blocks certificate issuance and material distribution
// while leaving TTL, health, status, static pages, and DNS unaffected.
func CertificateSuspension(service *certservice.Service) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !service.Suspended() {
				next.ServeHTTP(w, r)
				return
			}

			code := ""
			event := ""
			message := ""
			switch {
			case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/certs/"):
				code = issuanceSuspendedCode
				event = "certificate issuance request blocked"
				message = issuanceSuspendedMessage
			case r.Method == http.MethodGet &&
				strings.HasPrefix(r.URL.Path, "/certs/") &&
				!strings.HasSuffix(r.URL.Path, "/ttl"):
				code = downloadSuspendedCode
				event = "certificate download request blocked"
				message = downloadSuspendedMessage
			default:
				next.ServeHTTP(w, r)
				return
			}

			slog.Info(event, "path", r.URL.Path)
			w.Header().Set("Retry-After", suspensionRetryAfter)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error":   code,
				"message": message,
			})
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
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			// Asset names are readable rather than content-hashed, so they must
			// remain refreshable when branding changes.
			w.Header().Set("Cache-Control", "public, max-age=3600")
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}
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

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

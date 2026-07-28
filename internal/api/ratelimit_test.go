package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCertificateReadMiddleware(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limiter := NewRateLimiter(ctx, CertificateReadRPS, CertificateReadBurst)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := limiter.CertificateReadMiddleware(inner)

	request := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req = req.WithContext(WithHashedIP(req.Context(), "client-a"))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	for i := 0; i < CertificateReadBurst; i++ {
		assert.Equal(t, http.StatusNoContent, request(http.MethodGet, "/certs/192.168.1.50").Code)
	}

	rec := request(http.MethodGet, "/certs/192.168.1.50/fullchain.pem")
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "10", rec.Header().Get("Retry-After"))

	assert.Equal(t, http.StatusNoContent, request(http.MethodPost, "/certs/192.168.1.50").Code)
	assert.Equal(t, http.StatusNoContent, request(http.MethodGet, "/health").Code)
}

func TestInitialIssuanceRateLimiter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limiter := NewInitialIssuanceRateLimiter(ctx)

	for range InitialIssuanceBurst {
		allowed, retryAfter := limiter.AllowWithRetry("client-a")
		assert.True(t, allowed)
		assert.Zero(t, retryAfter)
	}

	allowed, retryAfter := limiter.AllowWithRetry("client-a")
	assert.False(t, allowed)
	assert.Greater(t, retryAfter, 23*time.Hour)
	assert.LessOrEqual(t, retryAfter, InitialIssuanceRefill)

	allowed, retryAfter = limiter.AllowWithRetry("client-b")
	assert.True(t, allowed)
	assert.Zero(t, retryAfter)
}

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func TestRateLimiterScopesClientIPs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limiter := NewRateLimiter(ctx, rate.Every(time.Hour), 2)
	assert.True(t, limiter.Allow("a"))
	assert.True(t, limiter.Allow("a"))
	assert.False(t, limiter.Allow("a"))
	assert.True(t, limiter.Allow("b"))
}

func TestLimitsApplyIndependentEndpointBucketsPerClientIP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limits := NewLimits(ctx)
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) })
	handler := limits.Middleware(inner)
	request := func(clientIP, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req = req.WithContext(WithHashedIP(req.Context(), clientIP))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder
	}

	for range RegistrationBurst {
		assert.Equal(t, http.StatusCreated, request("a", "/register/10.0.0.1").Code)
	}
	limited := request("a", "/register/10.0.0.1")
	assert.Equal(t, http.StatusTooManyRequests, limited.Code)
	assert.Equal(t, RegistrationRetryAfter, limited.Header().Get("Retry-After"))
	assert.Equal(t, http.StatusCreated, request("b", "/register/10.0.0.1").Code)

	for range UpdateBurst {
		assert.Equal(t, http.StatusCreated, request("a", "/update").Code)
	}
	limited = request("a", "/update")
	assert.Equal(t, http.StatusTooManyRequests, limited.Code)
	assert.Equal(t, UpdateRetryAfter, limited.Header().Get("Retry-After"))
	assert.Equal(t, http.StatusCreated, request("b", "/update").Code)
	assert.Equal(t, http.StatusCreated, request("a", "/unlimited").Code)
}

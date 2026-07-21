package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"lucor.dev/lancert/internal/certservice"
	"lucor.dev/lancert/internal/certstore"
	"lucor.dev/lancert/internal/dnssrv"
	"lucor.dev/lancert/internal/metrics"
)

// newTestHandler creates a handler backed by a temp cert store.
func newTestHandler(t *testing.T) *Handler {
	t.Helper()

	store := certstore.New(t.TempDir())
	txtStore := dnssrv.NewTXTStore()

	svc := certservice.New(
		certservice.Config{Zone: "lancert.dev", Staging: true},
		store,
		txtStore,
	)

	return New(svc, nil)
}

func TestHealth(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, "ok", body["status"])
}

func TestStatus(t *testing.T) {
	store := certstore.New(t.TempDir())
	svc := certservice.New(certservice.Config{Zone: "lancert.dev", Staging: true}, store, dnssrv.NewTXTStore())
	h := New(svc, func() metrics.Snapshot {
		return metrics.Snapshot{Queries24H: 12, WriteAttempts24H: 10, WriteSuccesses24H: 9, RecentQPS: 2.5, RecentWindow: time.Minute, RecentP95: 2 * time.Millisecond, TrackingComplete: true, ActiveTargets30D: 3, ActivePrefixes30D: 2, Readiness: metrics.Readiness{Available: true, Total: 3, Ready: 2}}
	})
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Certificate coverage")
	assert.Contains(t, rec.Body.String(), "2 of 3 · 66.7%")
}

func TestAssets(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/assets/lancert-logo.svg", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "image/svg+xml", rec.Header().Get("Content-Type"))

	req = httptest.NewRequest(http.MethodGet, "/assets/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestIndexAnalyticsOnlyOnCanonicalHost(t *testing.T) {
	h := newTestHandler(t)

	for _, test := range []struct {
		host      string
		analytics bool
	}{
		{host: "localhost:8080", analytics: false},
		{host: "192.168.1.50", analytics: false},
		{host: "preview.lancert.dev", analytics: false},
		{host: "lancert.dev", analytics: true},
		{host: "lancert.dev:443", analytics: true},
	} {
		t.Run(test.host, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Host = test.host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			containsScript := strings.Contains(rec.Body.String(), "analytics.lucor.dev/script.js")
			assert.Equal(t, test.analytics, containsScript)
		})
	}
}

func TestGetCert_NotFound(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/certs/192.168.1.50", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestGetCert_InvalidIP(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/certs/8.8.8.8", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestGetFullChain_NotFound(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/certs/192.168.1.50/fullchain.pem", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestGetFullChain_InvalidIP(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/certs/8.8.8.8/fullchain.pem", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestGetPrivKey_NotFound(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/certs/192.168.1.50/privkey.pem", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestGetPrivKey_InvalidIP(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/certs/8.8.8.8/privkey.pem", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestGetTTL_NotFound(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/certs/192.168.1.50/ttl", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestGetTTL_InvalidIP(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/certs/8.8.8.8/ttl", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestWriteError_RetryAfterOn5xx(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, http.StatusInternalServerError, "something broke")
	assert.Equal(t, "3600", rec.Header().Get("Retry-After"))

	rec = httptest.NewRecorder()
	writeError(rec, http.StatusBadRequest, "bad input")
	assert.Empty(t, rec.Header().Get("Retry-After"))
}

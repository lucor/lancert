package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"lucor.dev/lancert/internal/certservice"
	"lucor.dev/lancert/internal/certstore"
	"lucor.dev/lancert/internal/dnssrv"
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

	return New(svc)
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

func TestStats(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, float64(0), body["cert_count"])
	assert.Equal(t, float64(0), body["total_issued"])
	assert.Equal(t, float64(0), body["budget_used"])
	assert.Equal(t, float64(40), body["budget_limit"])
	assert.Contains(t, body, "budget_resets_in")
	assert.Equal(t, float64(0), body["pending_issuances"])
	assert.Equal(t, float64(0), body["failed_issuances"])
	assert.Contains(t, body, "uptime")
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

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{name: "days", d: 89*24*time.Hour + 12*time.Hour, want: "89d 12h"},
		{name: "hours only", d: 5*time.Hour + 30*time.Minute, want: "5h 30m"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, formatDuration(tt.d))
		})
	}
}

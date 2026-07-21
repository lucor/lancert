package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecurityHeadersCacheAssets(t *testing.T) {
	h := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	assetReq := httptest.NewRequest(http.MethodGet, "/assets/lancert-logo.svg", nil)
	assetRec := httptest.NewRecorder()
	h.ServeHTTP(assetRec, assetReq)
	assert.Equal(t, "nosniff", assetRec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "public, max-age=3600", assetRec.Header().Get("Cache-Control"))

	apiReq := httptest.NewRequest(http.MethodGet, "/health", nil)
	apiRec := httptest.NewRecorder()
	h.ServeHTTP(apiRec, apiReq)
	assert.Equal(t, "no-store", apiRec.Header().Get("Cache-Control"))
}

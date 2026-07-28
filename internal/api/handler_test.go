package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	acmeissue "lucor.dev/lancert/internal/acme"
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
		certservice.Config{Zone: "lancert.dev", Environment: acmeissue.EnvironmentStaging},
		store,
		txtStore,
		metrics.Disabled{},
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
	svc := certservice.New(certservice.Config{Zone: "lancert.dev", Environment: acmeissue.EnvironmentStaging}, store, dnssrv.NewTXTStore(), metrics.Disabled{})
	h := New(svc, func() metrics.Snapshot {
		return metrics.Snapshot{Queries24H: 12, WriteAttempts24H: 10, WriteSuccesses24H: 9, RecentQueries: 2, RecentWindow: time.Minute, ResponseP95: 2 * time.Millisecond, DailyLookups: []metrics.DailyLookup{{Date: "2026-07-20", Queries: 4}, {Date: "2026-07-21", Queries: 12}}, TrackingComplete: true, ActiveTargets30D: 3, ActivePrefixes30D: 2, Readiness: metrics.Readiness{Available: true, Total: 3, Ready: 2}, CertificateLifecycle: metrics.CertificateLifecycle{RecordedSince: time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC), InitialIssuances: 7, Renewals: 3, ARIRenewals: 2, TotalIssued: 10, ARIAdoption: 66.666, HasARIAdoption: true}}
	})
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Local address activity")
	assert.Contains(t, rec.Body.String(), "Certificates")
	assert.Contains(t, rec.Body.String(), "Certificates cached")
	assert.Contains(t, rec.Body.String(), "Total certificates issued")
	assert.Contains(t, rec.Body.String(), "ARI renewal activity")
	assert.Contains(t, rec.Body.String(), "2 of 3 renewals")
	assert.Contains(t, rec.Body.String(), "66.7%")
	assert.NotContains(t, rec.Body.String(), "Recorded since")
	assert.Contains(t, rec.Body.String(), "Serving certificates since 23 Jul 2026.")
	assert.Contains(t, rec.Body.String(), "Lookup trend")
	assert.Contains(t, rec.Body.String(), "21 Jul: 12 lookups")
	assert.Contains(t, rec.Body.String(), "dev (dev)")
}

func TestStatusBuildInfo(t *testing.T) {
	store := certstore.New(t.TempDir())
	svc := certservice.New(certservice.Config{Zone: "lancert.dev", Environment: acmeissue.EnvironmentStaging}, store, dnssrv.NewTXTStore(), metrics.Disabled{})
	h := NewWithBuildInfo(svc, nil, BuildInfo{Version: "v2026.07.24", CommitHash: "abcdef"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))

	assert.Contains(t, rec.Body.String(), ">v2026.07.24</a> (abcdef)")
	assert.Contains(t, rec.Body.String(), "https://github.com/lucor/lancert/releases/tag/v2026.07.24")
}

func TestStatusWithoutRenewals(t *testing.T) {
	store := certstore.New(t.TempDir())
	svc := certservice.New(certservice.Config{Zone: "lancert.dev", Environment: acmeissue.EnvironmentStaging}, store, dnssrv.NewTXTStore(), metrics.Disabled{})
	h := New(svc, func() metrics.Snapshot {
		return metrics.Snapshot{Readiness: metrics.Readiness{Available: true}, CertificateLifecycle: metrics.CertificateLifecycle{TotalIssued: 2}}
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "<strong>—</strong>")
	assert.Contains(t, rec.Body.String(), "Not available")
	assert.Contains(t, rec.Body.String(), "No certificate renewals have been recorded yet.")
	assert.NotContains(t, rec.Body.String(), "aria-label=\"ARI adoption\"")
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

func TestDocsPages(t *testing.T) {
	h := newTestHandler(t)

	for _, path := range []string{"/docs", "/docs/api", "/docs/web-servers"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
			assert.Contains(t, rec.Body.String(), "lancert")
		})
	}
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

func TestAnalyticsOnAllHTMLPages(t *testing.T) {
	h := newTestHandler(t)
	paths := []string{"/", "/docs", "/docs/api", "/docs/web-servers", "/status", "/missing"}

	for _, host := range []string{"lancert.dev", "preview.lancert.dev"} {
		for _, path := range paths {
			t.Run(host+path, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, path, nil)
				req.Host = host
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)

				containsScript := strings.Contains(rec.Body.String(), "analytics.lucor.dev/script.js")
				assert.Equal(t, host == "lancert.dev", containsScript)
			})
		}
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

func TestIssueCertInitialIssuanceRateLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limiter := NewInitialIssuanceRateLimiter(ctx)
	const clientKey = "client-a"
	for range InitialIssuanceBurst {
		assert.True(t, limiter.Allow(clientKey))
	}

	store := certstore.New(t.TempDir())
	svc := certservice.New(certservice.Config{Zone: "lancert.dev", Environment: acmeissue.EnvironmentStaging}, store, dnssrv.NewTXTStore(), metrics.Disabled{})
	h := New(svc, nil, WithInitialIssuanceLimiter(limiter))
	req := httptest.NewRequest(http.MethodPost, "/certs/192.168.1.50", nil)
	req = req.WithContext(WithIssuanceClientKey(req.Context(), clientKey))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
	retryAfter := rec.Header().Get("Retry-After")
	assert.NotEmpty(t, retryAfter)
	seconds, err := strconv.Atoi(retryAfter)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, seconds, int(InitialIssuanceRefill/time.Second))
	assert.Contains(t, rec.Body.String(), "initial certificate issuance rate limit exceeded")
}

func TestIssueCertCachedDoesNotConsumeInitialIssuanceCredit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	limiter := NewInitialIssuanceRateLimiter(ctx)
	const clientKey = "client-cache"
	for range InitialIssuanceBurst - 1 {
		require.True(t, limiter.Allow(clientKey))
	}

	store := certstore.New(t.TempDir())
	addr := netip.MustParseAddr("192.168.1.50")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cached"},
		DNSNames:  []string{"cached.lancert.dev"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
	}, &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	require.NoError(t, store.Save(addr, keyPEM, [][]byte{certDER}))

	svc := certservice.New(certservice.Config{Zone: "lancert.dev", Environment: acmeissue.EnvironmentStaging}, store, dnssrv.NewTXTStore(), metrics.Disabled{})
	h := New(svc, nil, WithInitialIssuanceLimiter(limiter))
	req := httptest.NewRequest(http.MethodPost, "/certs/192.168.1.50", nil).WithContext(WithIssuanceClientKey(context.Background(), clientKey))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// The cached request did not consume the last available token.
	require.True(t, limiter.Allow(clientKey))
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

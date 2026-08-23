package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.lucor.dev/lancert/internal/metrics"
	"go.lucor.dev/lancert/internal/registration"
)

const testChallenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type testAPI struct {
	handler  http.Handler
	store    *registration.Store
	recorder *testMetricsRecorder
}

type testMetricsRecorder struct {
	challengeUpdates []string
}

func (*testMetricsRecorder) RecordDNSQuery(string) {}

func (r *testMetricsRecorder) RecordChallengeUpdate(registrationID string) {
	r.challengeUpdates = append(r.challengeUpdates, registrationID)
}

func (*testMetricsRecorder) RecordResponse(bool, time.Duration) {}

func newTestAPI(t *testing.T) testAPI {
	t.Helper()
	store, err := registration.Open(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	snapshot := func() metrics.Snapshot {
		return metrics.Snapshot{
			Queries24H:                 42,
			ACMEActiveRegistrations30D: 3,
			ResponseP95:                1500 * time.Microsecond,
			FreshAt:                    time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
		}
	}
	recorder := &testMetricsRecorder{}
	h := NewWithBuildInfo(store, "lancert.dev.", snapshot, recorder, BuildInfo{Version: "v2", CommitHash: "abcdef"})
	return testAPI{handler: Chain(h, Recover, SecurityHeaders), store: store, recorder: recorder}
}

func perform(handler http.Handler, method, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func register(t *testing.T, api testAPI) registrationResponse {
	t.Helper()
	response := perform(api.handler, http.MethodPost, "/register/192.168.1.50", nil, nil)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var registered registrationResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &registered))
	return registered
}

func TestRegisterContract(t *testing.T) {
	api := newTestAPI(t)
	response := perform(api.handler, http.MethodPost, "/register/192.168.1.50", nil, map[string]string{"Accept-Encoding": "gzip"})
	require.Equal(t, http.StatusCreated, response.Code)
	assert.Equal(t, "application/json", response.Header().Get("Content-Type"))
	assert.Equal(t, CompatibilityVersion, response.Header().Get(compatibilityHeader))
	assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))
	assert.Empty(t, response.Header().Get("Content-Encoding"))

	var registered registrationResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &registered))
	assert.Regexp(t, `^[a-z]+-[a-z]+(?:-[a-z2-7]{2})?\.lancert\.dev$`, registered.Hostname)
	assert.Regexp(t, `^[a-z]+-[a-z]+(?:-[a-z2-7]{2})?$`, registered.Subdomain)
	assert.Equal(t, "_acme-challenge."+registered.Subdomain+".lancert.dev", registered.FullDomain)
	assert.NotEmpty(t, registered.Username)
	assert.Len(t, registered.Password, 40)
	_, ok := api.store.Lookup(registered.Subdomain)
	assert.True(t, ok)
}

func TestRegisterRejectsUnsupportedRoutesAddressesAndBodies(t *testing.T) {
	api := newTestAPI(t)
	tests := []struct {
		method string
		path   string
		body   []byte
		status int
	}{
		{http.MethodPost, "/register", nil, http.StatusNotFound},
		{http.MethodPost, "/register/192.168.1.50/extra", nil, http.StatusNotFound},
		{http.MethodGet, "/register/192.168.1.50", nil, http.StatusMethodNotAllowed},
		{http.MethodPost, "/register/8.8.8.8", nil, http.StatusBadRequest},
		{http.MethodPost, "/register/127.0.0.1", nil, http.StatusBadRequest},
		{http.MethodPost, "/register/fd00::1", nil, http.StatusBadRequest},
		{http.MethodPost, "/register/192.168.1.50", []byte("x"), http.StatusBadRequest},
	}
	for _, test := range tests {
		response := perform(api.handler, test.method, test.path, test.body, nil)
		assert.Equal(t, test.status, response.Code, "%s %s", test.method, test.path)
	}
}

func TestAcmeDNSUpdateContract(t *testing.T) {
	api := newTestAPI(t)
	registered := register(t, api)
	body, err := json.Marshal(updateRequest{Subdomain: registered.Subdomain, TXT: testChallenge})
	require.NoError(t, err)
	response := perform(api.handler, http.MethodPost, "/update", body, map[string]string{
		"Content-Type": "application/json",
		"X-Api-User":   registered.Username,
		"X-Api-Key":    registered.Password,
	})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	assert.JSONEq(t, `{"txt":"`+testChallenge+`"}`, response.Body.String())
	state, ok := api.store.Lookup(registered.Subdomain)
	require.True(t, ok)
	assert.Equal(t, testChallenge, state.Challenges[0])
	assert.Equal(t, []string{state.ID}, api.recorder.challengeUpdates)
}

func TestUpdateAuthorizationAndValidationResponses(t *testing.T) {
	api := newTestAPI(t)
	registered := register(t, api)
	validBody := `{"subdomain":"` + registered.Subdomain + `","txt":"` + testChallenge + `"}`
	tests := []struct {
		name    string
		body    string
		user    string
		key     string
		status  int
		errorID string
	}{
		{"missing headers", validBody, "", "", http.StatusUnauthorized, "forbidden"},
		{"unknown user", validBody, "unknown", registered.Password, http.StatusUnauthorized, "forbidden"},
		{"bad key", validBody, registered.Username, "bad", http.StatusUnauthorized, "forbidden"},
		{"other subdomain", `{"subdomain":"other","txt":"` + testChallenge + `"}`, registered.Username, registered.Password, http.StatusUnauthorized, "forbidden"},
		{"authenticated bad txt", `{"subdomain":"` + registered.Subdomain + `","txt":"bad"}`, registered.Username, registered.Password, http.StatusBadRequest, "bad_txt"},
		{"bad auth hides bad txt", `{"subdomain":"` + registered.Subdomain + `","txt":"bad"}`, registered.Username, "bad", http.StatusUnauthorized, "forbidden"},
		{"unknown field", `{"subdomain":"` + registered.Subdomain + `","txt":"` + testChallenge + `","other":true}`, registered.Username, registered.Password, http.StatusBadRequest, "bad_request"},
		{"trailing JSON", validBody + `{}`, registered.Username, registered.Password, http.StatusBadRequest, "bad_request"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := perform(api.handler, http.MethodPost, "/update", []byte(test.body), map[string]string{
				"X-Api-User": test.user,
				"X-Api-Key":  test.key,
			})
			assert.Equal(t, test.status, response.Code)
			assert.JSONEq(t, `{"error":"`+test.errorID+`"}`, response.Body.String())
		})
	}
	assert.Empty(t, api.recorder.challengeUpdates)
}

func TestHealthAndStatus(t *testing.T) {
	api := newTestAPI(t)
	health := perform(api.handler, http.MethodGet, "/health", nil, nil)
	assert.Equal(t, http.StatusOK, health.Code)
	assert.JSONEq(t, `{"status":"ok"}`, health.Body.String())

	status := perform(api.handler, http.MethodGet, "/status", nil, nil)
	assert.Equal(t, http.StatusOK, status.Code)
	assert.JSONEq(t, `{
		"status":"operational",
		"version":"v2",
		"commit":"abcdef",
		"api_version":"2",
		"metrics":{
			"available":true,
			"queries_24h":42,
			"acme_active_registrations_30d":3,
			"response_p95_ms":1.5,
			"updated_at":"2026-07-30T12:00:00Z"
		}
	}`, status.Body.String())
}

func TestPublicPages(t *testing.T) {
	api := newTestAPI(t)
	tests := []struct {
		path     string
		contains []string
		headers  map[string]string
	}{
		{"/assets/lancert-logo.svg", []string{"<svg"}, nil},
		{"/", []string{"Local HTTPS for private IP addresses", "lancert </span><span class=\"t-url\">192.168.1.50", "Prefer your own ACME client", "Why use lancert for local HTTPS", "How local HTTPS works", "Example: Caddy", "Let’s Encrypt", "rate limits", "lancert renew", "What do I trust Lancert with?"}, nil},
		{"/docs", []string{"Documentation", "Lancert CLI", "Use your own ACME client", "CLI", "Let’s Encrypt", "Renewal", "Certbot", "Lego", "acme.sh", "/docs/api"}, nil},
		{"/docs/cli", []string{"CLI Quickstart", "Install the CLI", "lancert 192.168.1.50", "Let’s Encrypt", "rate limits", "lancert renew", "Prefer another ACME client"}, nil},
		{"/docs/acme-clients", []string{"Use your own ACME client", "Register the target IP", "one-time-secret", "Certbot", "Lego", "acme.sh", "Caddy", "Nginx", "Traefik", "Renew the certificate"}, nil},
		{"/docs/api", []string{"api-reference", `data-url="/openapi.yaml"`, "Lancert v2"}, nil},
		{"/status", []string{"lancert status", "Service activity", "ACME-active registrations", "42", "1.50 ms"}, map[string]string{"Accept": "text/html"}},
		{"/openapi.yaml", []string{"openapi: 3.1.0", "/register/{ip}", "/update"}, nil},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			response := perform(api.handler, http.MethodGet, test.path, nil, test.headers)
			assert.Equal(t, http.StatusOK, response.Code)
			for _, expected := range test.contains {
				assert.Contains(t, response.Body.String(), expected)
			}
			for _, obsolete := range []string{"lancert-registration.json", "clients/", "download PEM", "certificate issuance", "certificate downloads", "Certificate availability", "ARI renewal", "Suspended"} {
				assert.NotContains(t, response.Body.String(), obsolete)
			}
		})
	}
	assert.Equal(t, http.StatusNotFound, perform(api.handler, http.MethodGet, "/docs/web-servers", nil, nil).Code)
}

func TestAnalyticsOnlyOnCanonicalHost(t *testing.T) {
	api := newTestAPI(t)
	paths := []string{"/", "/docs", "/docs/cli", "/docs/acme-clients", "/docs/api", "/status"}
	hosts := map[string]bool{
		"lancert.dev":         true,
		"lancert.dev:443":     true,
		"lancert.dev.":        true,
		"preview.lancert.dev": false,
		"localhost:8443":      false,
	}

	for host, expected := range hosts {
		for _, path := range paths {
			t.Run(host+path, func(t *testing.T) {
				request := httptest.NewRequest(http.MethodGet, path, nil)
				request.Host = host
				if path == "/status" {
					request.Header.Set("Accept", "text/html")
				}
				response := httptest.NewRecorder()
				api.handler.ServeHTTP(response, request)

				tracked := strings.Contains(response.Body.String(), "analytics.lucor.dev/script.js")
				assert.Equal(t, expected, tracked)
				assert.Contains(t, response.Header().Values("Vary"), "Host")
			})
		}
	}
}

func TestReadinessLifecycleIsStickyDuringShutdown(t *testing.T) {
	api := newTestAPI(t)
	handler := New(api.store, "lancert.dev.", nil, nil)

	handler.PrepareStartup()
	assert.Equal(t, http.StatusServiceUnavailable, perform(handler, http.MethodGet, "/health", nil, nil).Code)
	handler.MarkReady()
	assert.Equal(t, http.StatusOK, perform(handler, http.MethodGet, "/health", nil, nil).Code)
	handler.BeginShutdown()
	handler.MarkReady()
	assert.Equal(t, http.StatusServiceUnavailable, perform(handler, http.MethodGet, "/health", nil, nil).Code)
}

func TestStorageFailureDegradesHealth(t *testing.T) {
	api := newTestAPI(t)
	require.NoError(t, api.store.Close())
	response := perform(api.handler, http.MethodPost, "/register/10.0.0.1", nil, nil)
	assert.Equal(t, http.StatusInternalServerError, response.Code)
	assert.JSONEq(t, `{"error":"db_error"}`, response.Body.String())
	health := perform(api.handler, http.MethodGet, "/health", nil, nil)
	assert.Equal(t, http.StatusServiceUnavailable, health.Code)
	assert.JSONEq(t, `{"status":"degraded"}`, health.Body.String())
}

func TestUpdateBodyLimit(t *testing.T) {
	api := newTestAPI(t)
	registered := register(t, api)
	response := perform(api.handler, http.MethodPost, "/update", []byte(strings.Repeat("x", maxRequestBody+1)), map[string]string{
		"X-Api-User": registered.Username,
		"X-Api-Key":  registered.Password,
	})
	assert.Equal(t, http.StatusBadRequest, response.Code)
}

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
	clientFamilies   []metrics.ClientFamily
	userAgents       []string
}

func (*testMetricsRecorder) RecordDNSQuery(string) {}

func (r *testMetricsRecorder) RecordChallengeUpdate(registrationID string, clientFamily metrics.ClientFamily, userAgent string) {
	r.challengeUpdates = append(r.challengeUpdates, registrationID)
	r.clientFamilies = append(r.clientFamilies, clientFamily)
	r.userAgents = append(r.userAgents, userAgent)
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
			RegisteredQueries30D:       42,
			RegisteredQueriesTotal:     84,
			ClientFamilies:             []metrics.ClientFamilyActivity{{ClientFamily: "lancert-cli", AcceptedUpdates: 10}},
			DailyLookups:               []metrics.DailyLookup{{Date: "2026-07-30", Queries: 42}},
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
		{http.MethodPost, "/register/fc00::1", nil, http.StatusBadRequest},
		{http.MethodPost, "/register/fd12:3456:789a:1::25", nil, http.StatusCreated},
		{http.MethodPost, "/register/fd12%3A3456%3A789a%3A1%3A%3A25", nil, http.StatusCreated},
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
		"User-Agent":   "acme.sh/3.0.7 (https://github.com/acmesh-official/acme.sh)",
	})
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	assert.JSONEq(t, `{"txt":"`+testChallenge+`"}`, response.Body.String())
	state, ok := api.store.Lookup(registered.Subdomain)
	require.True(t, ok)
	assert.Equal(t, testChallenge, state.Challenges[0])
	assert.Equal(t, []string{state.ID}, api.recorder.challengeUpdates)
	assert.Equal(t, []metrics.ClientFamily{metrics.ClientFamilyACMESh}, api.recorder.clientFamilies)
	assert.Equal(t, []string{"acme.sh/3.0.7 (https://github.com/acmesh-official/acme.sh)"}, api.recorder.userAgents)
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
	assert.Empty(t, api.recorder.clientFamilies)
	assert.Empty(t, api.recorder.userAgents)
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
			"certificate_bootstrap_complete":false,
			"lets_encrypt_certificates_7d":0,
			"lets_encrypt_reissued_7d":0,
			"lets_encrypt_adopted_hostnames":0,
			"updated_at":"2026-07-30T12:00:00Z",
			"certificates_observed_30d":0,
			"certificates_observed_total":0,
			"certificate_monitor_degraded":false
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
		{"/docs/cli", []string{"CLI Quickstart", "Install the CLI", "brew install lucor/tap/lancert", "go install go.lucor.dev/lancert-cli/cmd/lancert@latest", "lancert 192.168.1.50", "Let’s Encrypt", "rate limits", "lancert renew", "Prefer another ACME client"}, nil},
		{"/docs/acme-clients", []string{"Use your own ACME client", "Register the target IP", "one-time-secret", "Certbot", "Lego", "acme.sh", "Caddy", "Nginx", "Traefik", "Renew the certificate"}, nil},
		{"/docs/api", []string{"api-reference", `data-url="/openapi.yaml"`, "Lancert v2"}, nil},
		{"/status", []string{"lancert status", "Adoption", "Registered hostnames", "DNS-01 active", "New hostnames", "With a Let's Encrypt certificate", "Address patterns", "IPv4", "IPv6 ULA", "IPv4 /24", "IPv6 /64", "ACME client activity", "Certificate activity", "lancert-cli", "42"}, map[string]string{"Accept": "text/html"}},
		{"/openapi.yaml", []string{"openapi: 3.1.0", "/register/{ip}", "/update"}, nil},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			response := perform(api.handler, http.MethodGet, test.path, nil, test.headers)
			assert.Equal(t, http.StatusOK, response.Code)
			for _, expected := range test.contains {
				assert.Contains(t, response.Body.String(), expected)
			}
			for _, obsolete := range []string{"lancert-registration.json", "clients/", "download PEM", "certificate downloads", "Certificate availability", "confirms ARI renewal", "Suspended"} {
				assert.NotContains(t, response.Body.String(), obsolete)
			}
		})
	}
	assert.Equal(t, http.StatusNotFound, perform(api.handler, http.MethodGet, "/docs/web-servers", nil, nil).Code)
}

func TestStatusShowsStatisticsSince(t *testing.T) {
	api := newTestAPI(t)
	register(t, api)

	response := perform(api.handler, http.MethodGet, "/status", nil, map[string]string{"Accept": "text/html"})
	require.Equal(t, http.StatusOK, response.Code)
	assert.Contains(t, response.Body.String(), "Usage statistics since")
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

func TestUsageCharts(t *testing.T) {
	now := time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC)
	registrations, dns := usageCharts(
		[]registration.DailyUsage{{Date: "2026-08-23", Hostnames: 2, PrivateIPs: 1}},
		[]metrics.DailyLookup{{Date: "2026-08-24", Queries: 50}},
		now,
	)
	require.Len(t, registrations, 30)
	require.Len(t, dns, 30)
	assert.Equal(t, usageChartPoint{Date: "2026-08-23", Label: "Aug 23", Hostnames: 2, PrivateIPs: 1, Height: 100}, registrations[28])
	assert.Equal(t, usageChartPoint{Date: "2026-08-24", Label: "Aug 24", Queries: 50, Height: 100}, dns[29])
}

func TestAdoptionSummary(t *testing.T) {
	usage := registration.Usage{
		Hostnames: 10, ACMEActiveHostnames: 7,
		Daily: []registration.DailyUsage{
			{Date: "2026-08-22", Hostnames: 2},
			{Date: "2026-09-14", Hostnames: 3},
			{Date: "2026-09-20", Hostnames: 4},
			{Date: "2026-09-21", Hostnames: 100},
		},
	}
	rate, new7, new30 := adoptionSummary(usage, time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC))
	assert.Equal(t, "70.0%", rate)
	assert.Equal(t, uint64(7), new7)
	assert.Equal(t, uint64(9), new30)
}

func TestUsageTablesAddRegisteredDNSQueries(t *testing.T) {
	usage := registration.Usage{
		Hostnames: 3,
		RegistrationTargets: map[string]string{
			"one":   "192.168.1.10",
			"two":   "192.168.1.10",
			"three": "10.42.0.1",
		},
		Prefixes: []registration.NetworkUsage{
			{Network: "192.168.1.0/24", Hostnames: 2, PrivateIPs: 1},
			{Network: "10.42.0.0/24", Hostnames: 1, PrivateIPs: 1},
		},
		IPs: []registration.PrivateIPUsage{
			{IP: "192.168.1.10", Hostnames: 2, ACMEActiveHostnames: 1},
			{IP: "10.42.0.1", Hostnames: 1, ACMEActiveHostnames: 1},
		},
	}
	lookups := []metrics.RegistrationLookup{
		{RegistrationID: "one", Queries: 20},
		{RegistrationID: "two", Queries: 5},
		{RegistrationID: "three", Queries: 50},
		{RegistrationID: "removed", Queries: 100},
	}

	ipv4, _ := usageTables(usage, lookups, 10)
	assert.Equal(t, []networkUsageView{
		{NetworkUsage: usage.Prefixes[0], DNSQueries30D: 25, Width: 67},
		{NetworkUsage: usage.Prefixes[1], DNSQueries30D: 50, Width: 34},
	}, ipv4.TopPrefixes)
	assert.Equal(t, []privateIPUsageView{
		{PrivateIPUsage: usage.IPs[0], DNSQueries30D: 25},
		{PrivateIPUsage: usage.IPs[1], DNSQueries30D: 50},
	}, ipv4.TopIPs)
	assert.Equal(t, []networkUsageView{ipv4.TopPrefixes[1], ipv4.TopPrefixes[0]}, ipv4.DNSPrefixes)
	assert.Equal(t, []privateIPUsageView{ipv4.TopIPs[1], ipv4.TopIPs[0]}, ipv4.DNSIPs)
}

func TestUsageTablesKeepIPv6QueriesSeparate(t *testing.T) {
	usage := registration.Usage{
		Hostnames: 1,
		RegistrationTargets: map[string]string{
			"ula": "fd12:3456:789a:1::25",
		},
		IPv6Prefixes: []registration.NetworkUsage{
			{Network: "fd12:3456:789a:1::/64", Hostnames: 1, PrivateIPs: 1},
		},
		IPv6IPs: []registration.PrivateIPUsage{
			{IP: "fd12:3456:789a:1::25", Hostnames: 1},
		},
	}
	lookups := []metrics.RegistrationLookup{{RegistrationID: "ula", Queries: 9}}

	ipv4, ipv6 := usageTables(usage, lookups, 10)
	assert.Empty(t, ipv4.TopPrefixes)
	assert.Empty(t, ipv4.TopIPs)
	assert.Equal(t, uint64(9), ipv6.TopPrefixes[0].DNSQueries30D)
	assert.Equal(t, uint64(9), ipv6.TopIPs[0].DNSQueries30D)
	assert.Equal(t, uint64(9), ipv6.DNSPrefixes[0].DNSQueries30D)
	assert.Equal(t, uint64(9), ipv6.DNSIPs[0].DNSQueries30D)
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

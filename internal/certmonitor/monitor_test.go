package certmonitor

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.lucor.dev/lancert/internal/metrics"
	"go.lucor.dev/lancert/internal/registration"
)

type testStore struct {
	after      string
	complete   bool
	pages      [][]metrics.CertificateIssuance
	statusErr  error
	refreshDue bool
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testResponse(r *http.Request, body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

func (s *testStore) InitializeSSLMate(context.Context, time.Time) error        { return nil }
func (s *testStore) BeginSSLMatePoll(context.Context, time.Time) (bool, error) { return true, nil }
func (s *testStore) SSLMateState(context.Context) (string, bool, error) {
	return s.after, s.complete, nil
}
func (s *testStore) SSLMateRevocationState(context.Context, time.Time) (string, bool, error) {
	return "", s.refreshDue, nil
}
func (s *testStore) RecordSSLMatePage(_ context.Context, events []metrics.CertificateIssuance, after string, complete bool) error {
	s.pages = append(s.pages, events)
	s.after, s.complete = after, s.complete || complete
	return nil
}
func (*testStore) RecordSSLMateRevocationPage(context.Context, []metrics.CertificateIssuance, string, bool) error {
	return nil
}
func (s *testStore) SetSSLMateMonitorStatus(_ context.Context, _ time.Time, err error) error {
	s.statusErr = err
	return nil
}
func (*testStore) RebuildSnapshot(context.Context) error { return nil }

func TestPollStoresMatchingIssuancesAndAdvancesThroughFilteredEntries(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		require.Equal(t, "Bearer secret", r.Header.Get("Authorization"))
		q := r.URL.Query()
		require.Equal(t, "lancert.dev", q.Get("domain"))
		require.Equal(t, "true", q.Get("include_subdomains"))
		require.Equal(t, "true", q.Get("match_wildcards"))
		require.ElementsMatch(t, []string{"dns_names", "issuer", "issuer.caa_domains", "revocation"}, q["expand"])
		if calls == 1 {
			require.Empty(t, q.Get("after"))
			return testResponse(r, `[
{"id":"1","tbs_sha256":"root","dns_names":["lancert.dev"],"not_before":"2026-09-01T00:00:00Z","not_after":"2026-12-01T00:00:00Z","revoked":false,"issuer":{"friendly_name":"Let's Encrypt","caa_domains":["letsencrypt.org"]}},
{"id":"2","tbs_sha256":"cert-1","dns_names":["*.alpha.lancert.dev","alpha.lancert.dev"],"not_before":"2026-09-02T00:00:00Z","not_after":"2026-12-02T00:00:00Z","revoked":true,"revocation":{"time":"2026-09-03T00:00:00Z","checked_at":"2026-09-04T00:00:00Z"},"issuer":{"friendly_name":"Example CA","caa_domains":["example.test"]}}
	]`), nil
		}
		require.Equal(t, "2", q.Get("after"))
		return testResponse(r, `[]`), nil
	})}

	store := &testStore{}
	monitor := &Monitor{store: store, zone: "lancert.dev", token: "secret", endpoint: "https://api.example.test/issuances", client: client, registrations: func(context.Context) ([]registration.CertificateRegistration, error) {
		return []registration.CertificateRegistration{{Hostname: "alpha"}}, nil
	}}
	require.NoError(t, monitor.Poll(context.Background()))
	require.Equal(t, 2, calls)
	require.Len(t, store.pages, 2)
	require.Len(t, store.pages[0], 1) // The apex entry is ignored; the registered hostname is retained.
	require.Equal(t, "Example CA", store.pages[0][0].Issuer)
	require.True(t, *store.pages[0][0].Revoked)
	require.Equal(t, time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC), *store.pages[0][0].RevocationTime)
	require.Equal(t, time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC), *store.pages[0][0].RevocationCheckedAt)
	require.Empty(t, store.pages[1])
	require.True(t, store.complete)
	require.Equal(t, "2", store.after)
}

func TestNormalizeNamesAndRegistrationMatch(t *testing.T) {
	names := normalizeNames([]string{" ALPHA.LANCERT.DEV.", "*.alpha.lancert.dev", "alpha.lancert.dev", "other.test"})
	require.Equal(t, []string{"*.alpha.lancert.dev", "alpha.lancert.dev", "other.test"}, names)
	require.True(t, matchesZone(names, "lancert.dev"))
	require.False(t, matchesZone([]string{"notlancert.dev"}, "lancert.dev"))
	require.Equal(t, []metrics.RegistrationIssuance{{Hostname: "alpha"}}, matchRegistrations(names, []registration.CertificateRegistration{{Hostname: "alpha"}, {Hostname: "beta"}}, "lancert.dev"))
}

func TestPollPersistsRevokedIssuancesFromAnyCA(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return testResponse(r, `[{"id":"1","tbs_sha256":"cert-1","dns_names":["alpha.lancert.dev"],"not_before":"2026-09-02T00:00:00Z","not_after":"2026-12-02T00:00:00Z","revoked":true,"issuer":{"friendly_name":"Example CA","caa_domains":["example.test"]}}]`), nil
	})}
	store := &testStore{}
	monitor := &Monitor{store: store, zone: "lancert.dev", endpoint: "https://api.example.test/issuances", client: client, registrations: func(context.Context) ([]registration.CertificateRegistration, error) {
		return []registration.CertificateRegistration{{Hostname: "alpha"}}, nil
	}}
	require.NoError(t, monitor.Poll(context.Background()))
	require.Len(t, store.pages[0], 1)
	require.Equal(t, "Example CA", store.pages[0][0].Issuer)
	require.Equal(t, []string{"example.test"}, store.pages[0][0].CAADomains)
	require.NotNil(t, store.pages[0][0].Revoked)
	require.True(t, *store.pages[0][0].Revoked)
	require.Equal(t, []string{"alpha.lancert.dev"}, store.pages[0][0].DNSNames)
	require.Equal(t, "alpha", store.pages[0][0].Registrations[0].Hostname)
	require.NoError(t, store.statusErr)
}

func TestDiscoveryContinuesWhenDailyRevocationRefreshFails(t *testing.T) {
	store := &testStore{after: "discovery-cursor", complete: true, refreshDue: true}
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls%2 == 1 {
			require.Equal(t, "discovery-cursor", r.URL.Query().Get("after"))
			return testResponse(r, `[]`), nil
		}
		require.Empty(t, r.URL.Query().Get("after"))
		response := testResponse(r, `{}`)
		response.StatusCode, response.Status = http.StatusServiceUnavailable, "503 Service Unavailable"
		return response, nil
	})}
	monitor := &Monitor{store: store, zone: "lancert.dev", endpoint: "https://api.example.test/issuances", client: client, registrations: func(context.Context) ([]registration.CertificateRegistration, error) {
		return nil, nil
	}}
	// A persistent refresh failure must not prevent the next discovery poll.
	require.Error(t, monitor.Poll(context.Background()))
	require.Error(t, monitor.Poll(context.Background()))
	require.Equal(t, 4, calls)
}

func TestDiscoveryAndRefreshShareRequestBudget(t *testing.T) {
	store := &testStore{after: "discovery-cursor", complete: true, refreshDue: true}
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return testResponse(r, `[]`), nil
		}
		return testResponse(r, `[{"id":"refresh-cursor","tbs_sha256":"known"}]`), nil
	})}
	monitor := &Monitor{store: store, zone: "lancert.dev", endpoint: "https://api.example.test/issuances", client: client, registrations: func(context.Context) ([]registration.CertificateRegistration, error) {
		return nil, nil
	}}
	require.NoError(t, monitor.Poll(context.Background()))
	require.Equal(t, maxPagesPerPoll, calls)
}

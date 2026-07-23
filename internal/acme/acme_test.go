package acme

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip implements http.RoundTripper for a test function.
func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRetryCaptureTransportKeepsOnlyLatestResponse(t *testing.T) {
	requests := 0
	transport := &retryCaptureTransport{base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		response := &http.Response{Header: make(http.Header), Request: req}
		if requests == 1 {
			response.Header.Set("Retry-After", "60")
		}
		return response, nil
	})}
	request, err := http.NewRequest(http.MethodGet, "https://example.test", nil)
	require.NoError(t, err)

	_, err = transport.RoundTrip(request)
	require.NoError(t, err)
	require.False(t, transport.retryAfterTime().IsZero())
	_, err = transport.RoundTrip(request)
	require.NoError(t, err)
	require.True(t, transport.retryAfterTime().IsZero())
}

func TestHTTPClientForHasPerRequestTimeout(t *testing.T) {
	client, _, err := httpClientFor(EnvironmentProduction, "", false)
	require.NoError(t, err)
	require.Equal(t, acmeHTTPTimeout, client.Timeout)
}

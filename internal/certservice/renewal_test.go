package certservice

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	acmeissue "lucor.dev/lancert/internal/acme"
)

func TestChooseRenewAtIsStableAndInsideWindow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	a := chooseRenewAt("cert-id", start, end)
	b := chooseRenewAt("cert-id", start, end)
	require.Equal(t, a, b)
	require.False(t, a.Before(start))
	require.True(t, a.Before(end))
}

func TestRetryAtPreservesAbsoluteUpstreamTime(t *testing.T) {
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	want := now.Add(15 * time.Minute)
	err := &acmeissue.RateLimitError{Err: errors.New("rate limited"), RetryAt: want}

	require.Equal(t, want, retryAt(err, now))
}

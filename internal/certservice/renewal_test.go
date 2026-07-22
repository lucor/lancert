package certservice

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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

package registration

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostnameSpaceIsCuratedAndDistinct(t *testing.T) {
	generated := make(map[string]struct{})
	for _, template := range hostnameTemplates {
		for _, left := range template.left {
			for _, right := range template.right {
				hostname := left + "-" + right
				require.True(t, validHostname(hostname), hostname)
				generated[hostname] = struct{}{}
			}
		}
	}
	assert.Len(t, generated, 20_480)
}

func TestGenerateHostname(t *testing.T) {
	hostname, err := generateHostname(bytes.NewReader([]byte{0, 0, 0}), false)
	require.NoError(t, err)
	assert.Equal(t, "agile-alpaca", hostname)

	hostname, err = generateHostname(bytes.NewReader([]byte{0, 0, 0, 10, 31}), true)
	require.NoError(t, err)
	assert.Equal(t, "agile-alpaca-k7", hostname)

	_, err = generateHostname(errorReader{}, false)
	assert.ErrorContains(t, err, "select template")
}

func TestValidHostnameTreatsTheLabelAsOpaque(t *testing.T) {
	for _, hostname := range []string{"quiet-otter", "quiet-otter-k7", "legacy2value"} {
		assert.True(t, validHostname(hostname), hostname)
	}
	for _, hostname := range []string{"", "Quiet-otter", "-quiet", "quiet-", "quiet.otter", "quiet_otter"} {
		assert.False(t, validHostname(hostname), hostname)
	}
	assert.False(t, validHostname(string(bytes.Repeat([]byte{'a'}, 64))))
}

func TestRandomIndexRejectsInvalidBuckets(t *testing.T) {
	_, err := randomIndex(bytes.NewReader(nil), 0)
	assert.ErrorContains(t, err, "invalid bucket size")
	_, err = randomIndex(bytes.NewReader(nil), 257)
	assert.ErrorContains(t, err, "invalid bucket size")
	_, err = randomIndex(errorReader{}, 2)
	assert.EqualError(t, err, "random failed")
}

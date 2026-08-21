package registration

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestChallengeStoreKeepsTwoNewestDistinctValues(t *testing.T) {
	now := time.Date(2026, time.August, 2, 10, 0, 0, 0, time.UTC)
	store := newChallengeStore(func() time.Time { return now }, challengeLifetime, time.Hour)
	t.Cleanup(store.Close)

	store.Set("quiet-otter", challengeA)
	store.Set("quiet-otter", challengeB)
	assert.Equal(t, [2]string{challengeB, challengeA}, store.Lookup("quiet-otter"))

	now = now.Add(time.Minute)
	store.Set("quiet-otter", challengeA)
	assert.Equal(t, [2]string{challengeA, challengeB}, store.Lookup("quiet-otter"))

	store.Set("quiet-otter", challengeC)
	assert.Equal(t, [2]string{challengeC, challengeA}, store.Lookup("quiet-otter"))
}

func TestChallengeStoreExpiresAndRemovesValues(t *testing.T) {
	now := time.Date(2026, time.August, 2, 10, 0, 0, 0, time.UTC)
	store := newChallengeStore(func() time.Time { return now }, challengeLifetime, time.Hour)
	t.Cleanup(store.Close)
	store.Set("quiet-otter", challengeA)

	now = now.Add(challengeLifetime)
	assert.Empty(t, store.Lookup("quiet-otter"))
	assert.NotContains(t, store.records, "quiet-otter")
}

func TestChallengeStorePeriodicallyPurgesExpiredValues(t *testing.T) {
	store := newChallengeStore(time.Now, 5*time.Millisecond, time.Millisecond)
	t.Cleanup(store.Close)
	store.Set("quiet-otter", challengeA)

	assert.Eventually(t, func() bool {
		store.mu.Lock()
		defer store.mu.Unlock()
		_, found := store.records["quiet-otter"]
		return !found
	}, time.Second, time.Millisecond)
}

func TestChallengeStoreCloseIsIdempotent(t *testing.T) {
	store := newChallengeStore(time.Now, challengeLifetime, time.Hour)
	store.Close()
	store.Close()
}

package metrics

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPersistenceUTCAndP95(t *testing.T) {
	now := time.Date(2026, 7, 21, 23, 59, 30, 0, time.UTC)
	clock := func() time.Time { return now }
	path := filepath.Join(t.TempDir(), "metrics.db")
	s, err := Open(path, WithClock(clock), WithoutBackground())
	require.NoError(t, err)
	for range 18 {
		s.RecordDNSQuery("registration-1")
		s.RecordResponse(true, time.Millisecond)
	}
	for range 2 {
		s.RecordDNSQuery("registration-1")
		s.RecordResponse(false, 100*time.Millisecond)
	}
	s.RecordChallengeUpdate("registration-1")
	s.RecordChallengeUpdate("registration-1")
	require.NoError(t, s.Flush(context.Background()))
	require.NoError(t, s.RebuildSnapshot(context.Background()))
	snap := s.Snapshot()
	require.Equal(t, uint64(20), snap.Queries24H)
	require.Equal(t, uint64(18), snap.WriteSuccesses24H)
	require.Equal(t, uint64(20), snap.RecentQueries)
	require.Equal(t, 100*time.Millisecond, snap.ResponseP95)
	require.Len(t, snap.DailyLookups, 30)
	require.Equal(t, DailyLookup{Date: "2026-07-21", Queries: 20}, snap.DailyLookups[29])
	require.Equal(t, uint64(20), snap.RegisteredQueries30D)
	require.Equal(t, uint64(20), snap.RegisteredQueriesTotal)
	require.Equal(t, []RegistrationLookup{{RegistrationID: "registration-1", Queries: 20}}, snap.RegistrationLookups30D)
	require.Equal(t, uint64(1), snap.ActiveRegistrations30D)
	require.Equal(t, uint64(1), snap.ACMEActiveRegistrations30D)
	require.Equal(t, uint64(2), snap.ChallengeUpdates30D)
	require.NoError(t, s.Close(context.Background()))

	s, err = Open(path, WithClock(clock), WithoutBackground())
	require.NoError(t, err)
	require.Equal(t, uint64(20), s.Snapshot().Queries24H)
	// Crossing midnight creates a separate UTC-date aggregate.
	now = now.Add(time.Minute)
	s.RecordDNSQuery("registration-1")
	s.RecordResponse(true, time.Millisecond)
	require.NoError(t, s.Close(context.Background()))
}

func TestDateOfNormalizesNonUTCTime(t *testing.T) {
	local := time.Date(2026, 7, 21, 23, 30, 0, 0, time.FixedZone("local", 3600))
	require.Equal(t, "2026-07-21", dateOf(local))
}

func TestRegistrationActivityIsRetained(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	s, err := Open(filepath.Join(t.TempDir(), "metrics.db"), WithClock(func() time.Time { return now }), WithoutBackground())
	require.NoError(t, err)
	_, err = s.db.Exec(`INSERT INTO registration_activity_daily(date,registration_id,dns_queries,challenge_updates) VALUES('2026-06-16','old',1,1)`)
	require.NoError(t, err)
	s.RecordDNSQuery("current")
	require.NoError(t, s.Flush(context.Background()))

	var rows int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM registration_activity_daily WHERE registration_id='old'`).Scan(&rows))
	require.Equal(t, 1, rows)
	require.NoError(t, s.RebuildSnapshot(context.Background()))
	snap := s.Snapshot()
	require.Equal(t, uint64(1), snap.ActiveRegistrations30D)
	require.Zero(t, snap.ACMEActiveRegistrations30D)
	require.NoError(t, s.Close(context.Background()))
}

func TestConcurrentRecordFlushSnapshot(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "metrics.db"), WithoutBackground())
	require.NoError(t, err)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 500 {
				s.RecordDNSQuery("registration-1")
				s.RecordResponse(true, time.Millisecond)
			}
		}()
	}
	for range 5 {
		require.NoError(t, s.Flush(context.Background()))
	}
	wg.Wait()
	require.NoError(t, s.Flush(context.Background()))
	require.NoError(t, s.RebuildSnapshot(context.Background()))
	require.Equal(t, uint64(4000), s.Snapshot().Queries24H)
	require.NoError(t, s.Close(context.Background()))
}

func TestUnavailable(t *testing.T) {
	_, err := Open(t.TempDir(), WithoutBackground())
	require.Error(t, err)
	snap := UnavailableSnapshot(err)
	require.True(t, snap.Unavailable)
	var recorder Recorder = Disabled{}
	recorder.RecordDNSQuery("")
	recorder.RecordChallengeUpdate("")
	recorder.RecordResponse(false, 0)
}

func TestQueriesAndResponsesAreIndependent(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 30, 0, time.UTC)
	s, err := Open(filepath.Join(t.TempDir(), "metrics.db"), WithClock(func() time.Time { return now }), WithoutBackground())
	require.NoError(t, err)

	// A query for an unknown owner still contributes to operational DNS totals.
	s.RecordDNSQuery("")
	s.RecordResponse(true, 2*time.Millisecond)
	// One response containing two registered questions records two queries, but
	// still only one response-write observation.
	s.RecordDNSQuery("registration-1")
	s.RecordDNSQuery("registration-2")
	s.RecordResponse(false, 300*time.Millisecond)
	require.NoError(t, s.Flush(context.Background()))
	require.NoError(t, s.RebuildSnapshot(context.Background()))
	snap := s.Snapshot()
	require.Equal(t, uint64(3), snap.Queries24H)
	require.Equal(t, uint64(2), snap.RegisteredQueries30D)
	require.Equal(t, uint64(2), snap.RegisteredQueriesTotal)
	require.Equal(t, uint64(2), snap.WriteAttempts24H)
	require.Equal(t, uint64(1), snap.WriteSuccesses24H)
	require.Equal(t, uint64(2), snap.ActiveRegistrations30D)
	var latencyCount, latencySumUS, latencyMaxUS uint64
	require.NoError(t, s.db.QueryRow(`SELECT latency_count,latency_sum_us,latency_max_us FROM dns_hourly`).Scan(&latencyCount, &latencySumUS, &latencyMaxUS))
	require.Equal(t, uint64(2), latencyCount)
	require.Equal(t, uint64((302 * time.Millisecond).Microseconds()), latencySumUS)
	require.Equal(t, uint64((300 * time.Millisecond).Microseconds()), latencyMaxUS)
	require.True(t, snap.ResponseP95Overflow)
	require.Equal(t, LatencyBounds[len(LatencyBounds)-1], snap.ResponseP95)
	require.NoError(t, s.Close(context.Background()))
}

func TestDatabaseModeAndPragmas(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.db")
	require.NoError(t, os.WriteFile(path, nil, 0o644))
	s, err := Open(path, WithoutBackground())
	require.NoError(t, err)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	var journal string
	var timeout int
	require.NoError(t, s.db.QueryRow(`PRAGMA journal_mode`).Scan(&journal))
	require.Equal(t, "delete", journal)
	require.NoError(t, s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&timeout))
	require.Equal(t, 5000, timeout)
	var version int
	var dirty bool
	require.NoError(t, s.db.QueryRow(`SELECT version,dirty FROM schema_migrations`).Scan(&version, &dirty))
	require.Equal(t, 1, version)
	require.False(t, dirty)
	require.NoError(t, s.Close(context.Background()))
}

func TestRecentWindowUsesStartupTime(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	s, err := Open(filepath.Join(t.TempDir(), "metrics.db"), WithClock(func() time.Time { return now }), WithoutBackground())
	require.NoError(t, err)
	s.RecordDNSQuery("registration-1")
	now = now.Add(15 * time.Second)
	require.NoError(t, s.RebuildSnapshot(context.Background()))
	require.Equal(t, 15*time.Second, s.Snapshot().RecentWindow)
	require.Equal(t, uint64(1), s.Snapshot().RecentQueries)
	now = now.Add(-time.Minute)
	require.NoError(t, s.RebuildSnapshot(context.Background()))
	require.Zero(t, s.Snapshot().RecentWindow)
	require.Zero(t, s.Snapshot().RecentQueries)
	require.NoError(t, s.Close(context.Background()))
}

func TestRegistrationActivityAccumulatesAfterReopen(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "metrics.db")
	open := func() *Store {
		s, err := Open(path, WithClock(func() time.Time { return now }), WithoutBackground())
		require.NoError(t, err)
		return s
	}

	s := open()
	s.RecordDNSQuery("registration-1")
	s.RecordChallengeUpdate("registration-1")
	require.NoError(t, s.Close(context.Background()))

	s = open()
	s.RecordDNSQuery("registration-1")
	s.RecordDNSQuery("registration-2")
	require.NoError(t, s.Flush(context.Background()))
	var queries, updates uint64
	require.NoError(t, s.db.QueryRow(`SELECT dns_queries,challenge_updates FROM registration_activity_daily WHERE registration_id='registration-1'`).Scan(&queries, &updates))
	require.Equal(t, uint64(2), queries)
	require.Equal(t, uint64(1), updates)
	require.NoError(t, s.RebuildSnapshot(context.Background()))
	require.Equal(t, uint64(2), s.Snapshot().ActiveRegistrations30D)
	require.Equal(t, uint64(1), s.Snapshot().ACMEActiveRegistrations30D)
	require.NoError(t, s.Close(context.Background()))
}

func BenchmarkRecordMethods(b *testing.B) {
	s := &Store{
		cfg:           config{now: time.Now},
		pendingHourly: make(map[time.Time]aggregate),
		pendingDaily:  make(map[string]map[string]registrationActivity),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		s.RecordDNSQuery("registration-1")
		s.RecordChallengeUpdate("registration-1")
		s.RecordResponse(true, time.Millisecond)
	}
}

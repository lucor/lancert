package metrics

import (
	"context"
	"net/netip"
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
	ip := netip.MustParseAddr("192.168.1.2")
	for range 18 {
		s.RecordTarget(ip)
		s.RecordResponse(true, time.Millisecond)
	}
	for range 2 {
		s.RecordTarget(ip)
		s.RecordResponse(false, 100*time.Millisecond)
	}
	require.NoError(t, s.Flush(context.Background()))
	require.NoError(t, s.RebuildSnapshot(context.Background()))
	snap := s.Snapshot()
	require.Equal(t, uint64(20), snap.Queries24H)
	require.Equal(t, uint64(18), snap.WriteSuccesses24H)
	require.Equal(t, uint64(20), snap.RecentQueries)
	require.Equal(t, 100*time.Millisecond, snap.ResponseP95)
	require.Len(t, snap.DailyLookups, 30)
	require.Equal(t, DailyLookup{Date: "2026-07-21", Queries: 20}, snap.DailyLookups[29])
	require.Equal(t, uint64(1), snap.ActiveTargets30D)
	require.Equal(t, uint64(1), snap.ActivePrefixes30D)
	require.NoError(t, s.Close(context.Background()))

	s, err = Open(path, WithClock(clock), WithoutBackground())
	require.NoError(t, err)
	require.Equal(t, uint64(20), s.Snapshot().Queries24H)
	// Crossing midnight creates a separate UTC-date aggregate.
	now = now.Add(time.Minute)
	s.RecordTarget(ip)
	s.RecordResponse(true, time.Millisecond)
	require.NoError(t, s.Close(context.Background()))
}

func TestDateOfNormalizesNonUTCTime(t *testing.T) {
	local := time.Date(2026, 7, 21, 23, 30, 0, 0, time.FixedZone("local", 3600))
	require.Equal(t, "2026-07-21", dateOf(local))
}

func TestCertificateLifecyclePersistsAndDerivesAdoption(t *testing.T) {
	now := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "metrics.db")
	s, err := Open(path, WithClock(func() time.Time { return now }), WithoutBackground())
	require.NoError(t, err)
	require.NoError(t, s.RecordInitialIssuance(context.Background()))
	require.NoError(t, s.RecordRenewal(context.Background(), false))
	require.NoError(t, s.RecordRenewal(context.Background(), true))
	require.NoError(t, s.RebuildSnapshot(context.Background()))
	lifecycle := s.Snapshot().CertificateLifecycle
	require.Equal(t, now, lifecycle.RecordedSince)
	require.Equal(t, uint64(1), lifecycle.InitialIssuances)
	require.Equal(t, uint64(2), lifecycle.Renewals)
	require.Equal(t, uint64(1), lifecycle.ARIRenewals)
	require.Equal(t, uint64(3), lifecycle.TotalIssued)
	require.True(t, lifecycle.HasARIAdoption)
	require.InDelta(t, 50.0, lifecycle.ARIAdoption, 0.001)
	require.NoError(t, s.Close(context.Background()))

	s, err = Open(path, WithClock(func() time.Time { return now.Add(time.Hour) }), WithoutBackground())
	require.NoError(t, err)
	require.Equal(t, now, s.Snapshot().CertificateLifecycle.RecordedSince)
	require.Equal(t, uint64(3), s.Snapshot().CertificateLifecycle.TotalIssued)
	require.NoError(t, s.Close(context.Background()))
}

func TestCertificateLifecycleAdoptionUnavailableWithoutRenewals(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "metrics.db"), WithoutBackground())
	require.NoError(t, err)
	lifecycle := s.Snapshot().CertificateLifecycle
	require.False(t, lifecycle.HasARIAdoption)
	require.NoError(t, s.Close(context.Background()))
}

func TestInitializeCertificateLifecycleSeedsOnlyOnce(t *testing.T) {
	now := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	s, err := Open(filepath.Join(t.TempDir(), "metrics.db"), WithClock(func() time.Time { return now }), WithoutBackground())
	require.NoError(t, err)
	require.NoError(t, s.InitializeCertificateLifecycle(context.Background(), 4, time.Time{}))
	lifecycle := s.Snapshot().CertificateLifecycle
	require.Equal(t, now, lifecycle.RecordedSince)
	require.Equal(t, uint64(4), lifecycle.InitialIssuances)

	now = now.Add(time.Hour)
	require.NoError(t, s.InitializeCertificateLifecycle(context.Background(), 99, now))
	require.Equal(t, uint64(4), s.Snapshot().CertificateLifecycle.InitialIssuances)
	require.Equal(t, time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC), s.Snapshot().CertificateLifecycle.RecordedSince)
	require.NoError(t, s.Close(context.Background()))
}

func TestRetentionAndIncompletePropagation(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	s, err := Open(filepath.Join(t.TempDir(), "metrics.db"), WithClock(func() time.Time { return now }), WithoutBackground())
	require.NoError(t, err)
	_, err = s.db.Exec(`INSERT INTO target_activity_daily VALUES('2026-06-16',167772161,1),('2026-06-17',167772162,1),('2026-07-01',167772163,1);
INSERT INTO kpi_daily VALUES('2026-07-01',1,1,0)`)
	require.NoError(t, err)
	s.RecordTarget(netip.MustParseAddr("10.0.0.4"))
	s.RecordResponse(true, time.Millisecond)
	require.NoError(t, s.Flush(context.Background()))
	var old int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM target_activity_daily WHERE date='2026-06-16'`).Scan(&old))
	require.Zero(t, old)
	require.NoError(t, s.RebuildSnapshot(context.Background()))
	snap := s.Snapshot()
	require.False(t, snap.TrackingComplete)
	require.Zero(t, snap.ActiveTargets30D)
	require.NoError(t, s.Close(context.Background()))
}

func TestConcurrentRecordFlushSnapshot(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "metrics.db"), WithoutBackground())
	require.NoError(t, err)
	ip := netip.MustParseAddr("172.16.2.3")
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 500 {
				s.RecordTarget(ip)
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
	recorder.RecordTarget(netip.Addr{})
	recorder.RecordResponse(false, 0)
}

func TestTargetsAndResponsesAreIndependent(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 30, 0, time.UTC)
	s, err := Open(filepath.Join(t.TempDir(), "metrics.db"), WithClock(func() time.Time { return now }), WithoutBackground())
	require.NoError(t, err)

	// A TXT/no-target message still records its sole write and latency.
	s.RecordResponse(true, 2*time.Millisecond)
	// One response containing two valid target questions records two queries,
	// but still only one response-write observation.
	s.RecordTarget(netip.MustParseAddr("10.0.0.1"))
	s.RecordTarget(netip.MustParseAddr("10.0.0.2"))
	s.RecordResponse(false, 300*time.Millisecond)
	require.NoError(t, s.Flush(context.Background()))
	require.NoError(t, s.RebuildSnapshot(context.Background()))
	snap := s.Snapshot()
	require.Equal(t, uint64(2), snap.Queries24H)
	require.Equal(t, uint64(2), snap.WriteAttempts24H)
	require.Equal(t, uint64(1), snap.WriteSuccesses24H)
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
	require.NoError(t, s.Close(context.Background()))
}

func TestRecentWindowUsesStartupTime(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	s, err := Open(filepath.Join(t.TempDir(), "metrics.db"), WithClock(func() time.Time { return now }), WithoutBackground())
	require.NoError(t, err)
	s.RecordTarget(netip.MustParseAddr("192.168.1.1"))
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

func TestTargetCapRestoredOnReopen(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "metrics.db")
	open := func() *Store {
		s, err := Open(path, WithClock(func() time.Time { return now }), WithoutBackground())
		require.NoError(t, err)
		return s
	}
	s := open()
	for i := range targetLimit {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		s.RecordTarget(ip)
		s.RecordResponse(true, time.Millisecond)
	}
	require.NoError(t, s.Flush(context.Background()))
	require.NoError(t, s.Close(context.Background()))
	s = open()
	s.RecordTarget(netip.MustParseAddr("10.255.255.255"))
	s.RecordResponse(true, time.Millisecond)
	// A restored address still accumulates after the cap is reached.
	s.RecordTarget(netip.MustParseAddr("10.0.0.1"))
	s.RecordResponse(true, time.Millisecond)
	require.NoError(t, s.Flush(context.Background()))
	var targets, existingQueries int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM target_activity_daily`).Scan(&targets))
	require.Equal(t, targetLimit, targets)
	require.NoError(t, s.db.QueryRow(`SELECT queries FROM target_activity_daily WHERE target=?`, int64(0x0a000001)).Scan(&existingQueries))
	require.Equal(t, 2, existingQueries)
	require.NoError(t, s.RebuildSnapshot(context.Background()))
	require.False(t, s.Snapshot().TrackingComplete)
	require.NoError(t, s.Close(context.Background()))
}

func TestSetReadinessClearsRecoveredReadinessError(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "metrics.db"), WithoutBackground())
	require.NoError(t, err)

	s.SetReadiness(Readiness{Degraded: true, Error: "certificate scan failed"})
	require.True(t, s.Snapshot().Degraded)
	require.Equal(t, "certificate scan failed", s.Snapshot().Error)

	s.SetReadiness(Readiness{Available: true})
	require.False(t, s.Snapshot().Degraded)
	require.Empty(t, s.Snapshot().Error)
	require.NoError(t, s.Close(context.Background()))
}

func TestSetReadinessPreservesIndependentSnapshotError(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "metrics.db"), WithoutBackground())
	require.NoError(t, err)

	s.SetReadiness(Readiness{Degraded: true, Error: "certificate scan failed"})
	s.snapMu.Lock()
	s.snap.Error = "target tracking incomplete"
	s.snap.TrackingComplete = false
	s.snapMu.Unlock()

	s.SetReadiness(Readiness{Available: false})
	require.True(t, s.Snapshot().Degraded)
	require.Equal(t, "target tracking incomplete", s.Snapshot().Error)
	require.NoError(t, s.Close(context.Background()))
}

func BenchmarkRecordMethods(b *testing.B) {
	s := &Store{cfg: config{now: time.Now}, pendingHourly: make(map[time.Time]aggregate), pendingDaily: make(map[string]map[uint32]uint64), current: make(map[uint32]uint64), dropped: make(map[string]uint64)}
	ip := netip.MustParseAddr("192.168.1.2")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		s.RecordTarget(ip)
		s.RecordResponse(true, time.Millisecond)
	}
}

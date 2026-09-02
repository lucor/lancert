package registration

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

const (
	challengeA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	challengeB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	challengeC = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
)

func TestRegisterShapesAndValidation(t *testing.T) {
	s, err := Open(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	credentials, err := s.Register(context.Background(), netip.MustParseAddr("192.168.1.50"))
	require.NoError(t, err)
	assert.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, credentials.ID)
	assert.Regexp(t, `^[a-z]+-[a-z]+$`, credentials.Hostname)
	assert.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, credentials.Username)
	assert.Len(t, credentials.Password, 40)
	assert.Regexp(t, `^[A-Za-z0-9_-]{40}$`, credentials.Password)

	for _, addr := range []netip.Addr{
		{}, netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("169.254.1.1"),
		netip.MustParseAddr("fd00::1"),
	} {
		_, err := s.Register(context.Background(), addr)
		assert.ErrorIs(t, err, ErrInvalidAddress)
	}
}

func TestPersistenceDigestPermissionsUsageAndEphemeralChallenges(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	path := filepath.Join(dir, "core.db")
	now := time.Date(2026, time.August, 2, 10, 20, 30, 0, time.UTC)
	s, err := Open(path, WithClock(func() time.Time { return now }))
	require.NoError(t, err)
	credentials, err := s.Register(context.Background(), netip.MustParseAddr("172.16.0.1"))
	require.NoError(t, err)

	var digest []byte
	require.NoError(t, s.db.QueryRow(`SELECT api_key_digest FROM registrations WHERE id=?`, credentials.ID).Scan(&digest))
	assert.Len(t, digest, 32)
	assert.NotEqual(t, []byte(credentials.Password), digest)
	var targetIP string
	require.NoError(t, s.db.QueryRow(`SELECT target_ip FROM registrations WHERE id=?`, credentials.ID).Scan(&targetIP))
	assert.Equal(t, "172.16.0.1", targetIP)
	var challengeCount int64
	var challengeUpdatedAt sql.NullInt64
	require.NoError(t, s.db.QueryRow(`SELECT challenge_count,challenge_updated_at FROM registrations WHERE id=?`, credentials.ID).Scan(&challengeCount, &challengeUpdatedAt))
	assert.Zero(t, challengeCount)
	assert.False(t, challengeUpdatedAt.Valid)
	var challengeTables int
	require.NoError(t, s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='challenge_slots'`).Scan(&challengeTables))
	assert.Zero(t, challengeTables)
	assert.NoError(t, updateChallenge(s, credentials.Username, credentials.Password, credentials.Hostname, challengeA))
	assert.NoError(t, updateChallenge(s, credentials.Username, credentials.Password, credentials.Hostname, challengeB))
	assert.Equal(t, [2]string{challengeB, challengeA}, mustLookup(t, s, credentials.Hostname).Challenges)
	require.NoError(t, s.db.QueryRow(`SELECT challenge_count,challenge_updated_at FROM registrations WHERE id=?`, credentials.ID).Scan(&challengeCount, &challengeUpdatedAt))
	assert.Equal(t, int64(2), challengeCount)
	assert.Equal(t, sql.NullInt64{Int64: now.Unix(), Valid: true}, challengeUpdatedAt)
	require.NoError(t, s.Close())

	dirInfo, err := os.Stat(dir)
	require.NoError(t, err)
	dbInfo, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())
	assert.Equal(t, os.FileMode(0o600), dbInfo.Mode().Perm())
	file, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(file), credentials.Password)
	assert.NotContains(t, string(file), challengeA)
	assert.NotContains(t, string(file), challengeB)

	s, err = Open(path, WithClock(func() time.Time { return now }))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	registration, ok := s.Lookup(credentials.Hostname)
	require.True(t, ok)
	assert.Equal(t, credentials.ID, registration.ID)
	assert.Equal(t, credentials.Hostname, registration.Hostname)
	assert.Equal(t, netip.MustParseAddr("172.16.0.1"), registration.TargetIP)
	assert.Empty(t, registration.Challenges, "ephemeral challenges must not survive restart")
	assert.NoError(t, updateChallenge(s, credentials.Username, credentials.Password, credentials.Hostname, challengeC))
	require.NoError(t, s.db.QueryRow(`SELECT challenge_count FROM registrations WHERE id=?`, credentials.ID).Scan(&challengeCount))
	assert.Equal(t, int64(3), challengeCount)

	var busyTimeout int
	var journalMode string
	require.NoError(t, s.db.QueryRow(`PRAGMA busy_timeout`).Scan(&busyTimeout))
	require.NoError(t, s.db.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode))
	assert.Equal(t, 5000, busyTimeout)
	assert.Equal(t, "delete", journalMode)
}

func TestSchemaMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core.db")
	s, err := Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	var version int
	var dirty bool
	require.NoError(t, s.db.QueryRow(`SELECT version,dirty FROM schema_migrations`).Scan(&version, &dirty))
	assert.Equal(t, 1, version)
	assert.False(t, dirty)
}

func TestUsageStats(t *testing.T) {
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	s, err := Open(":memory:", WithClock(func() time.Time { return now }))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	first, err := s.Register(context.Background(), netip.MustParseAddr("192.168.1.10"))
	require.NoError(t, err)
	_, err = s.Register(context.Background(), netip.MustParseAddr("192.168.1.10"))
	require.NoError(t, err)
	require.NoError(t, updateChallenge(s, first.Username, first.Password, first.Hostname, challengeA))
	now = now.AddDate(0, 0, 1)
	_, err = s.Register(context.Background(), netip.MustParseAddr("10.42.0.1"))
	require.NoError(t, err)
	now = now.AddDate(0, 0, 1)
	_, err = s.Register(context.Background(), netip.MustParseAddr("172.16.2.3"))
	require.NoError(t, err)

	usage, err := s.UsageStats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint64(4), usage.Hostnames)
	assert.Equal(t, uint64(3), usage.PrivateIPs)
	assert.Equal(t, uint64(1), usage.ACMEActiveHostnames)
	assert.Equal(t, time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC), usage.Since)
	assert.Len(t, usage.RegistrationTargets, 4)
	assert.Equal(t, "192.168.1.10", usage.RegistrationTargets[first.ID])
	assert.Equal(t, []DailyUsage{
		{Date: "2026-08-21", Hostnames: 2, PrivateIPs: 1},
		{Date: "2026-08-22", Hostnames: 1, PrivateIPs: 1},
		{Date: "2026-08-23", Hostnames: 1, PrivateIPs: 1},
	}, usage.Daily)
	assert.Equal(t, []NetworkUsage{
		{Network: "10.0.0.0/8", Hostnames: 1, PrivateIPs: 1},
		{Network: "172.16.0.0/12", Hostnames: 1, PrivateIPs: 1},
		{Network: "192.168.0.0/16", Hostnames: 2, PrivateIPs: 1},
	}, usage.Blocks)
	assert.Equal(t, []NetworkUsage{
		{Network: "192.168.1.0/24", Hostnames: 2, PrivateIPs: 1},
		{Network: "10.42.0.0/24", Hostnames: 1, PrivateIPs: 1},
		{Network: "172.16.2.0/24", Hostnames: 1, PrivateIPs: 1},
	}, usage.Prefixes)
	assert.Equal(t, []PrivateIPUsage{
		{IP: "192.168.1.10", Hostnames: 2, ACMEActiveHostnames: 1},
		{IP: "10.42.0.1", Hostnames: 1},
		{IP: "172.16.2.3", Hostnames: 1},
	}, usage.IPs)
}

func TestRegisterAddsSuffixAfterPlainHostnameCollisions(t *testing.T) {
	var suffixRequests int
	hostnameGenerator := func(_ io.Reader, withSuffix bool) (string, error) {
		if withSuffix {
			suffixRequests++
			return "quiet-otter-k7", nil
		}
		return "quiet-otter", nil
	}
	s, err := Open(":memory:", func(cfg *config) { cfg.hostnameGenerator = hostnameGenerator })
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	first, err := s.Register(context.Background(), netip.MustParseAddr("10.0.0.1"))
	require.NoError(t, err)
	second, err := s.Register(context.Background(), netip.MustParseAddr("10.0.0.2"))
	require.NoError(t, err)

	assert.Equal(t, "quiet-otter", first.Hostname)
	assert.Equal(t, "quiet-otter-k7", second.Hostname)
	assert.Equal(t, 1, suffixRequests)
}

func TestAuthorizationChallengeValidationAndReplacement(t *testing.T) {
	s, err := Open(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	c, err := s.Register(context.Background(), netip.MustParseAddr("10.1.2.3"))
	require.NoError(t, err)

	for _, test := range []struct{ user, key, subdomain string }{
		{"unknown", c.Password, c.Hostname},
		{c.Username, "bad", c.Hostname},
		{c.Username, c.Password, "other"},
	} {
		assert.ErrorIs(t, updateChallenge(s, test.user, test.key, test.subdomain, challengeA), ErrForbidden)
	}
	assert.ErrorIs(t, updateChallenge(s, c.Username, c.Password, c.Hostname, "bad"), ErrInvalidChallenge)
	assert.ErrorIs(t, updateChallenge(s, c.Username, "bad", c.Hostname, "bad"), ErrForbidden)

	registrationID, err := s.UpdateChallenge(context.Background(), c.Username, c.Password, c.Hostname, challengeA)
	require.NoError(t, err)
	assert.Equal(t, c.ID, registrationID)
	require.NoError(t, updateChallenge(s, c.Username, c.Password, c.Hostname, challengeB))
	assert.Equal(t, [2]string{challengeB, challengeA}, mustLookup(t, s, c.Hostname).Challenges)
	require.NoError(t, updateChallenge(s, c.Username, c.Password, c.Hostname, challengeA))
	assert.Equal(t, [2]string{challengeA, challengeB}, mustLookup(t, s, c.Hostname).Challenges)
	require.NoError(t, updateChallenge(s, c.Username, c.Password, c.Hostname, challengeC))
	assert.Equal(t, [2]string{challengeC, challengeA}, mustLookup(t, s, c.Hostname).Challenges)
}

func TestConcurrentUpdatesKeepLatestCommittedDistinctValues(t *testing.T) {
	s, err := Open(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	c, err := s.Register(context.Background(), netip.MustParseAddr("192.168.2.2"))
	require.NoError(t, err)

	values := make([]string, 12)
	for i := range values {
		values[i] = string(bytes.Repeat([]byte{byte('A' + i)}, 43))
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(values))
	for _, value := range values {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- updateChallenge(s, c.Username, c.Password, c.Hostname, value)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	view := mustLookup(t, s, c.Hostname)
	assert.NotEmpty(t, view.Challenges[0])
	assert.NotEmpty(t, view.Challenges[1])
	assert.NotEqual(t, view.Challenges[0], view.Challenges[1])
	var challengeCount int64
	var challengeUpdatedAt sql.NullInt64
	require.NoError(t, s.db.QueryRow(`SELECT challenge_count,challenge_updated_at FROM registrations WHERE id=?`, c.ID).Scan(&challengeCount, &challengeUpdatedAt))
	assert.Equal(t, int64(12), challengeCount)
	assert.True(t, challengeUpdatedAt.Valid)
}

func TestDisabledRegistrationExcludedAfterReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core.db")
	s, err := Open(path)
	require.NoError(t, err)
	c, err := s.Register(context.Background(), netip.MustParseAddr("10.0.0.8"))
	require.NoError(t, err)
	require.NoError(t, s.Close())

	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE registrations SET status='disabled',disabled_at=123 WHERE id=?`, c.ID)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	s, err = Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	_, ok := s.Lookup(c.Hostname)
	assert.False(t, ok)
	assert.ErrorIs(t, updateChallenge(s, c.Username, c.Password, c.Hostname, challengeA), ErrForbidden)
}

func TestAPIKeyDigestDomainSeparator(t *testing.T) {
	digest := digestKey("test-secret")
	assert.Equal(t, "99212d29cdbf45962d48b8fa9fd96c930f3e785d61863dc0c180e1365b81c87a", fmt.Sprintf("%x", digest))
}

func mustLookup(t *testing.T, s *Store, hostname string) Registration {
	t.Helper()
	r, ok := s.Lookup(hostname)
	require.True(t, ok)
	return r
}

func updateChallenge(s *Store, username, key, subdomain, value string) error {
	_, err := s.UpdateChallenge(context.Background(), username, key, subdomain, value)
	return err
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("random failed") }

// Package metrics records and persists privacy-preserving DNS aggregates.
package metrics

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"go.lucor.dev/lancert/internal/migrations"
	_ "modernc.org/sqlite"
)

// LatencyBounds are the inclusive upper bounds of the fixed latency histogram.
// The final bucket contains values greater than the final bound.
var LatencyBounds = [...]time.Duration{
	100 * time.Microsecond, 250 * time.Microsecond, 500 * time.Microsecond,
	time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond,
	10 * time.Millisecond, 25 * time.Millisecond, 50 * time.Millisecond,
	100 * time.Millisecond, 250 * time.Millisecond,
}

const histogramLen = len(LatencyBounds) + 1

// Recorder accepts the small set of observations produced by the API and DNS
// serving paths.
type Recorder interface {
	RecordDNSQuery(registrationID string)
	RecordChallengeUpdate(registrationID string)
	RecordResponse(writeSucceeded bool, latency time.Duration)
}

// Disabled is a fail-open recorder. It intentionally discards every event.
type Disabled struct{}

func (Disabled) RecordDNSQuery(string)              {}
func (Disabled) RecordChallengeUpdate(string)       {}
func (Disabled) RecordResponse(bool, time.Duration) {}

// DailyLookup is the registered-host DNS query count for one UTC date.
type DailyLookup struct {
	Date    string
	Queries uint64
}

// RegistrationLookup is the registered-host DNS query count for one registration.
type RegistrationLookup struct {
	RegistrationID string
	Queries        uint64
}

// Snapshot is a point-in-time copy of the metrics used by status endpoints.
type Snapshot struct {
	Queries24H                 uint64
	WriteAttempts24H           uint64
	WriteSuccesses24H          uint64
	RecentQueries              uint64
	RecentWindow               time.Duration
	ResponseP95                time.Duration
	ResponseP95Overflow        bool
	DailyLookups               []DailyLookup
	RegistrationLookups30D     []RegistrationLookup
	RegisteredQueries30D       uint64
	RegisteredQueriesTotal     uint64
	ActiveRegistrations30D     uint64
	ACMEActiveRegistrations30D uint64
	ChallengeUpdates30D        uint64
	FreshAt                    time.Time
	Degraded                   bool
	Unavailable                bool
	Error                      string
	LastFlushAt                time.Time
	LastFlushError             string
}

// Option configures a Store.
type Option func(*config)

type config struct {
	now              func() time.Time
	flushInterval    time.Duration
	snapshotInterval time.Duration
	startWorker      bool
}

// WithClock supplies a clock (primarily for deterministic tests).
func WithClock(now func() time.Time) Option { return func(c *config) { c.now = now } }

// WithIntervals changes background flush and snapshot rebuild intervals.
func WithIntervals(flush, snapshot time.Duration) Option {
	return func(c *config) { c.flushInterval, c.snapshotInterval = flush, snapshot }
}

// WithoutBackground disables the worker. Flush and RebuildSnapshot remain usable.
func WithoutBackground() Option { return func(c *config) { c.startWorker = false } }

type aggregate struct {
	queries, attempts, successes             uint64
	latencyCount, latencySumUS, latencyMaxUS uint64
	hist                                     [histogramLen]uint64
}

type minuteBucket struct {
	minute time.Time
	aggregate
}

type registrationActivity struct {
	dnsQueries       uint64
	challengeUpdates uint64
}

// Store buffers aggregate observations in memory and persists them to SQLite.
type Store struct {
	db      *sql.DB
	cfg     config
	started time.Time

	mu            sync.Mutex
	pendingHourly map[time.Time]aggregate
	pendingDaily  map[string]map[string]registrationActivity
	recent        [5]minuteBucket

	flushMu      sync.Mutex
	snapMu       sync.RWMutex
	snap         Snapshot
	stop         chan struct{}
	done         chan struct{}
	closeOnce    sync.Once
	lastFlushAt  time.Time
	lastFlushErr error
}

// Open opens path, migrates it, and starts the background workers.
func Open(path string, options ...Option) (*Store, error) {
	c := config{now: time.Now, flushInterval: time.Minute, snapshotInterval: time.Minute, startWorker: true}
	for _, option := range options {
		option(&c)
	}
	if c.now == nil || c.flushInterval <= 0 || c.snapshotInterval <= 0 {
		return nil, errors.New("metrics: invalid option")
	}
	if path != ":memory:" {
		f, err := os.OpenFile(path, os.O_CREATE, 0o600)
		if err != nil {
			return nil, fmt.Errorf("metrics: create: %w", err)
		}
		if err = f.Close(); err != nil {
			return nil, fmt.Errorf("metrics: create: %w", err)
		}
		if err = os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("metrics: chmod: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("metrics: open: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err = db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		db.Close()
		return nil, fmt.Errorf("metrics: configure: %w", err)
	}
	if err = migrations.RunMetrics(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("metrics: migrate: %w", err)
	}
	s := &Store{db: db, cfg: c, started: c.now().UTC(), pendingHourly: make(map[time.Time]aggregate), pendingDaily: make(map[string]map[string]registrationActivity), stop: make(chan struct{}), done: make(chan struct{})}
	err = s.RebuildSnapshot(context.Background())
	if err != nil {
		db.Close()
		return nil, err
	}
	if c.startWorker {
		go s.run()
	} else {
		close(s.done)
	}
	return s, nil
}

// UnavailableSnapshot returns a status value suitable for fail-open wiring.
func UnavailableSnapshot(err error) Snapshot {
	s := Snapshot{Unavailable: true, Degraded: true}
	if err != nil {
		s.Error = err.Error()
	}
	return s
}

func dateOf(t time.Time) string      { return t.UTC().Format("2006-01-02") }
func hourOf(t time.Time) time.Time   { return t.UTC().Truncate(time.Hour) }
func minuteOf(t time.Time) time.Time { return t.UTC().Truncate(time.Minute) }

func histIndex(d time.Duration) int {
	for i, bound := range LatencyBounds {
		if d <= bound {
			return i
		}
	}
	return histogramLen - 1
}

// RecordDNSQuery records one DNS request and, when known, its registration.
func (s *Store) RecordDNSQuery(registrationID string) {
	now := s.cfg.now().UTC()
	hour, minute, date := hourOf(now), minuteOf(now), dateOf(now)
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.pendingHourly[hour]
	a.queries++
	s.pendingHourly[hour] = a
	i := int(minute.Unix() / 60 % 5)
	if i < 0 {
		i += 5
	}
	if s.recent[i].minute != minute {
		s.recent[i] = minuteBucket{minute: minute}
	}
	r := &s.recent[i].aggregate
	r.queries++
	if registrationID != "" {
		s.recordActivity(date, registrationID, registrationActivity{dnsQueries: 1})
	}
}

// RecordChallengeUpdate records one authenticated, accepted DNS-01 update.
func (s *Store) RecordChallengeUpdate(registrationID string) {
	if registrationID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recordActivity(dateOf(s.cfg.now()), registrationID, registrationActivity{challengeUpdates: 1})
}

func (s *Store) recordActivity(date, registrationID string, observation registrationActivity) {
	if s.pendingDaily[date] == nil {
		s.pendingDaily[date] = make(map[string]registrationActivity)
	}
	activity := s.pendingDaily[date][registrationID]
	activity.dnsQueries += observation.dnsQueries
	activity.challengeUpdates += observation.challengeUpdates
	s.pendingDaily[date][registrationID] = activity
}

// RecordResponse records one DNS response-write observation without SQL or I/O.
func (s *Store) RecordResponse(writeSucceeded bool, latency time.Duration) {
	now := s.cfg.now().UTC()
	hour, minute := hourOf(now), minuteOf(now)
	us := latency.Microseconds()
	if us < 0 {
		us = 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.pendingHourly[hour]
	recordResponse(&a, writeSucceeded, latency, uint64(us))
	s.pendingHourly[hour] = a
	i := int(minute.Unix() / 60 % 5)
	if i < 0 {
		i += 5
	}
	if s.recent[i].minute != minute {
		s.recent[i] = minuteBucket{minute: minute}
	}
	recordResponse(&s.recent[i].aggregate, writeSucceeded, latency, uint64(us))
}

func recordResponse(a *aggregate, succeeded bool, latency time.Duration, us uint64) {
	a.attempts++
	if succeeded {
		a.successes++
	}
	a.latencyCount++
	a.latencySumUS += us
	if us > a.latencyMaxUS {
		a.latencyMaxUS = us
	}
	a.hist[histIndex(latency)]++
}

func (s *Store) run() {
	ft, st := time.NewTicker(s.cfg.flushInterval), time.NewTicker(s.cfg.snapshotInterval)
	defer func() { ft.Stop(); st.Stop(); close(s.done) }()
	for {
		select {
		case <-ft.C:
			_ = s.Flush(context.Background())
		case <-st.C:
			_ = s.Flush(context.Background())
			_ = s.RebuildSnapshot(context.Background())
		case <-s.stop:
			return
		}
	}
}

// Flush atomically swaps pending RAM state and persists it transactionally.
func (s *Store) Flush(ctx context.Context) error {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	s.mu.Lock()
	hours, days := s.pendingHourly, s.pendingDaily
	s.pendingHourly, s.pendingDaily = make(map[time.Time]aggregate), make(map[string]map[string]registrationActivity)
	s.mu.Unlock()
	err := s.flushBatch(ctx, hours, days)
	s.mu.Lock()
	if err == nil {
		s.lastFlushAt = s.cfg.now().UTC()
		s.lastFlushErr = nil
	} else {
		s.lastFlushErr = err
	}
	s.mu.Unlock()
	if err != nil {
		s.mu.Lock()
		for k, v := range hours {
			a := s.pendingHourly[k]
			addAggregate(&a, v)
			s.pendingHourly[k] = a
		}
		for date, registrations := range days {
			if s.pendingDaily[date] == nil {
				s.pendingDaily[date] = make(map[string]registrationActivity)
			}
			for registrationID, activity := range registrations {
				pending := s.pendingDaily[date][registrationID]
				pending.dnsQueries += activity.dnsQueries
				pending.challengeUpdates += activity.challengeUpdates
				s.pendingDaily[date][registrationID] = pending
			}
		}
		s.mu.Unlock()
	}
	return err
}

func addAggregate(a *aggregate, b aggregate) {
	a.queries += b.queries
	a.attempts += b.attempts
	a.successes += b.successes
	a.latencyCount += b.latencyCount
	a.latencySumUS += b.latencySumUS
	if b.latencyMaxUS > a.latencyMaxUS {
		a.latencyMaxUS = b.latencyMaxUS
	}
	for i := range a.hist {
		a.hist[i] += b.hist[i]
	}
}

func (s *Store) flushBatch(ctx context.Context, hours map[time.Time]aggregate, days map[string]map[string]registrationActivity) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for hour, a := range hours {
		_, err = tx.ExecContext(ctx, `INSERT INTO dns_hourly(hour,queries,write_attempts,write_successes,latency_count,latency_sum_us,latency_max_us,h0,h1,h2,h3,h4,h5,h6,h7,h8,h9,h10,h11) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(hour) DO UPDATE SET queries=queries+excluded.queries,write_attempts=write_attempts+excluded.write_attempts,write_successes=write_successes+excluded.write_successes,latency_count=latency_count+excluded.latency_count,latency_sum_us=latency_sum_us+excluded.latency_sum_us,latency_max_us=MAX(latency_max_us,excluded.latency_max_us),h0=h0+excluded.h0,h1=h1+excluded.h1,h2=h2+excluded.h2,h3=h3+excluded.h3,h4=h4+excluded.h4,h5=h5+excluded.h5,h6=h6+excluded.h6,h7=h7+excluded.h7,h8=h8+excluded.h8,h9=h9+excluded.h9,h10=h10+excluded.h10,h11=h11+excluded.h11`, hour.Format(time.RFC3339), a.queries, a.attempts, a.successes, a.latencyCount, a.latencySumUS, a.latencyMaxUS, a.hist[0], a.hist[1], a.hist[2], a.hist[3], a.hist[4], a.hist[5], a.hist[6], a.hist[7], a.hist[8], a.hist[9], a.hist[10], a.hist[11])
		if err != nil {
			return err
		}
	}
	for date, registrations := range days {
		for registrationID, activity := range registrations {
			if _, err = tx.ExecContext(ctx, `INSERT INTO registration_activity_daily(date,registration_id,dns_queries,challenge_updates) VALUES(?,?,?,?) ON CONFLICT(date,registration_id) DO UPDATE SET dns_queries=dns_queries+excluded.dns_queries,challenge_updates=challenge_updates+excluded.challenge_updates`, date, registrationID, activity.dnsQueries, activity.challengeUpdates); err != nil {
				return err
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("metrics: flush: %w", err)
	}
	return nil
}

// RebuildSnapshot reads SQLite and recent RAM into a new snapshot.
func (s *Store) RebuildSnapshot(ctx context.Context) error {
	now := s.cfg.now().UTC()
	cutoff := now.Add(-23 * time.Hour).Truncate(time.Hour).Format(time.RFC3339)
	var out Snapshot
	out.FreshAt = now
	var responseHist [histogramLen]uint64
	row := s.db.QueryRowContext(ctx, `SELECT COALESCE(sum(queries),0),COALESCE(sum(write_attempts),0),COALESCE(sum(write_successes),0),COALESCE(sum(h0),0),COALESCE(sum(h1),0),COALESCE(sum(h2),0),COALESCE(sum(h3),0),COALESCE(sum(h4),0),COALESCE(sum(h5),0),COALESCE(sum(h6),0),COALESCE(sum(h7),0),COALESCE(sum(h8),0),COALESCE(sum(h9),0),COALESCE(sum(h10),0),COALESCE(sum(h11),0) FROM dns_hourly WHERE hour>=?`, cutoff)
	if err := row.Scan(&out.Queries24H, &out.WriteAttempts24H, &out.WriteSuccesses24H, &responseHist[0], &responseHist[1], &responseHist[2], &responseHist[3], &responseHist[4], &responseHist[5], &responseHist[6], &responseHist[7], &responseHist[8], &responseHist[9], &responseHist[10], &responseHist[11]); err != nil {
		return s.snapshotError(err)
	}
	out.ResponseP95, out.ResponseP95Overflow = percentile95(responseHist)
	startDate, endDate := now.AddDate(0, 0, -29).Format("2006-01-02"), dateOf(now)
	dailyRows, err := s.db.QueryContext(ctx, `SELECT date,sum(dns_queries) FROM registration_activity_daily WHERE date BETWEEN ? AND ? GROUP BY date`, startDate, endDate)
	if err != nil {
		return s.snapshotError(err)
	}
	daily := make(map[string]uint64)
	for dailyRows.Next() {
		var date string
		var queries uint64
		if err = dailyRows.Scan(&date, &queries); err != nil {
			dailyRows.Close()
			return s.snapshotError(err)
		}
		daily[date] = queries
	}
	if err = dailyRows.Close(); err != nil {
		return s.snapshotError(err)
	}
	for day := now.AddDate(0, 0, -29); !day.After(now); day = day.AddDate(0, 0, 1) {
		date := dateOf(day)
		out.DailyLookups = append(out.DailyLookups, DailyLookup{Date: date, Queries: daily[date]})
		out.RegisteredQueries30D += daily[date]
	}
	if err = s.db.QueryRowContext(ctx, `SELECT COALESCE(sum(dns_queries),0) FROM registration_activity_daily`).Scan(&out.RegisteredQueriesTotal); err != nil {
		return s.snapshotError(err)
	}
	lookupRows, err := s.db.QueryContext(ctx, `SELECT registration_id,sum(dns_queries) FROM registration_activity_daily WHERE date BETWEEN ? AND ? GROUP BY registration_id`, startDate, endDate)
	if err != nil {
		return s.snapshotError(err)
	}
	for lookupRows.Next() {
		var lookup RegistrationLookup
		if err = lookupRows.Scan(&lookup.RegistrationID, &lookup.Queries); err != nil {
			lookupRows.Close()
			return s.snapshotError(err)
		}
		out.RegistrationLookups30D = append(out.RegistrationLookups30D, lookup)
	}
	if err = lookupRows.Close(); err != nil {
		return s.snapshotError(err)
	}
	const activityQuery = `
SELECT count(*),
       COALESCE(sum(CASE WHEN challenge_updates > 0 THEN 1 ELSE 0 END),0),
       COALESCE(sum(challenge_updates),0)
FROM (
    SELECT registration_id,sum(challenge_updates) AS challenge_updates
    FROM registration_activity_daily
    WHERE date BETWEEN ? AND ?
    GROUP BY registration_id
)`
	if err = s.db.QueryRowContext(ctx, activityQuery, startDate, endDate).Scan(
		&out.ActiveRegistrations30D,
		&out.ACMEActiveRegistrations30D,
		&out.ChallengeUpdates30D,
	); err != nil {
		return s.snapshotError(err)
	}
	s.mu.Lock()
	lastFlushAt, lastFlushErr := s.lastFlushAt, s.lastFlushErr
	var recent aggregate
	for _, b := range s.recent {
		if !b.minute.IsZero() && now.Sub(b.minute) < 5*time.Minute && now.Sub(b.minute) >= 0 {
			addAggregate(&recent, b.aggregate)
		}
	}
	s.mu.Unlock()
	out.RecentWindow = now.Sub(s.started)
	if out.RecentWindow > 5*time.Minute {
		out.RecentWindow = 5 * time.Minute
	}
	if out.RecentWindow < 0 {
		out.RecentWindow = 0
	}
	out.RecentQueries = recent.queries
	out.LastFlushAt = lastFlushAt
	if lastFlushErr != nil {
		out.Degraded = true
		out.LastFlushError = lastFlushErr.Error()
	}
	s.snapMu.Lock()
	s.snap = out
	s.snapMu.Unlock()
	return nil
}

func (s *Store) snapshotError(err error) error {
	s.snapMu.Lock()
	s.snap.Degraded = true
	s.snap.Error = err.Error()
	s.snapMu.Unlock()
	return err
}

func percentile95(h [histogramLen]uint64) (time.Duration, bool) {
	var total uint64
	for _, n := range h {
		total += n
	}
	if total == 0 {
		return 0, false
	}
	want := (total*95 + 99) / 100
	var n uint64
	for i, v := range h {
		n += v
		if n >= want {
			if i < len(LatencyBounds) {
				return LatencyBounds[i], false
			}
			return LatencyBounds[len(LatencyBounds)-1], true
		}
	}
	return 0, false
}

// Snapshot returns a deep copy and never accesses SQLite.
func (s *Store) Snapshot() Snapshot {
	s.snapMu.RLock()
	defer s.snapMu.RUnlock()
	r := s.snap
	r.DailyLookups = append([]DailyLookup(nil), r.DailyLookups...)
	r.RegistrationLookups30D = append([]RegistrationLookup(nil), r.RegistrationLookups30D...)
	return r
}

// Close stops workers and makes one final flush and snapshot attempt.
func (s *Store) Close(ctx context.Context) error {
	var err error
	s.closeOnce.Do(func() {
		close(s.stop)
		<-s.done
		if e := s.Flush(ctx); e != nil {
			err = e
		} else if e = s.RebuildSnapshot(ctx); e != nil {
			err = e
		}
		if e := s.db.Close(); err == nil {
			err = e
		}
	})
	return err
}

// Package metrics records and persists privacy-preserving DNS KPI aggregates.
package metrics

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const targetLimit = 20_000

// LatencyBounds are the inclusive upper bounds of the fixed latency histogram.
// The final bucket contains values greater than the final bound.
var LatencyBounds = [...]time.Duration{
	100 * time.Microsecond, 250 * time.Microsecond, 500 * time.Microsecond,
	time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond,
	10 * time.Millisecond, 25 * time.Millisecond, 50 * time.Millisecond,
	100 * time.Millisecond, 250 * time.Millisecond,
}

const histogramLen = len(LatencyBounds) + 1

// Recorder is the minimal interface needed by the DNS serving path.
type Recorder interface {
	RecordTarget(target netip.Addr)
	RecordResponse(writeSucceeded bool, latency time.Duration)
}

// Disabled is a fail-open recorder. It intentionally discards every event.
type Disabled struct{}

func (Disabled) RecordTarget(netip.Addr)            {}
func (Disabled) RecordResponse(bool, time.Duration) {}

// Breakdown is a query-volume-ranked KPI item.
type Breakdown struct {
	Name    string
	Queries uint64
}

// DailyLookup is an aggregate count for one UTC date.
type DailyLookup struct {
	Date    string
	Queries uint64
}

// Readiness is the current certificate cache readiness result. It is kept
// separate from historical DNS aggregates because the certificate store is
// mutable and is rescanned periodically.
type Readiness struct {
	Total     uint64
	Ready     uint64
	Available bool
	Degraded  bool
	Error     string
}

// Snapshot is a point-in-time copy. Snapshot() deep-copies its slices, so a
// caller cannot mutate the copy retained by the metrics service.
type Snapshot struct {
	Queries24H          uint64
	WriteAttempts24H    uint64
	WriteSuccesses24H   uint64
	RecentQueries       uint64
	RecentWindow        time.Duration
	ResponseP95         time.Duration
	ResponseP95Overflow bool
	DailyLookups        []DailyLookup
	ActiveTargets30D    uint64
	ActivePrefixes30D   uint64
	TopBlocks           []Breakdown
	TopPrefixes         []Breakdown
	TopTargets          []Breakdown
	OtherBlockQueries   uint64
	OtherPrefixQueries  uint64
	OtherTargetQueries  uint64
	TrackingComplete    bool
	FreshAt             time.Time
	Degraded            bool
	Unavailable         bool
	Error               string
	LastFlushAt         time.Time
	LastFlushError      string
	Readiness           Readiness
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

type targetQuery struct {
	ip uint32
	q  uint64
}

// Store is a bounded-memory recorder backed by SQLite.
type Store struct {
	db      *sql.DB
	cfg     config
	started time.Time

	mu            sync.Mutex
	pendingHourly map[time.Time]aggregate
	pendingDaily  map[string]map[uint32]uint64
	recent        [5]minuteBucket
	currentDate   string
	current       map[uint32]uint64
	dropped       map[string]uint64

	flushMu      sync.Mutex
	snapMu       sync.RWMutex
	snap         Snapshot
	stop         chan struct{}
	done         chan struct{}
	closeOnce    sync.Once
	lastFlushAt  time.Time
	lastFlushErr error
	readiness    Readiness
}

// Open opens path, migrates it, restores today's cap state, and starts workers.
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
	s := &Store{db: db, cfg: c, started: c.now().UTC(), pendingHourly: make(map[time.Time]aggregate), pendingDaily: make(map[string]map[uint32]uint64), current: make(map[uint32]uint64), dropped: make(map[string]uint64), stop: make(chan struct{}), done: make(chan struct{})}
	if err = s.migrate(context.Background()); err == nil {
		err = s.restore(context.Background())
	}
	if err == nil {
		err = s.RebuildSnapshot(context.Background())
	}
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

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS dns_hourly (hour TEXT PRIMARY KEY, queries INTEGER NOT NULL, write_attempts INTEGER NOT NULL, write_successes INTEGER NOT NULL, latency_count INTEGER NOT NULL, latency_sum_us INTEGER NOT NULL, latency_max_us INTEGER NOT NULL, h0 INTEGER NOT NULL, h1 INTEGER NOT NULL, h2 INTEGER NOT NULL, h3 INTEGER NOT NULL, h4 INTEGER NOT NULL, h5 INTEGER NOT NULL, h6 INTEGER NOT NULL, h7 INTEGER NOT NULL, h8 INTEGER NOT NULL, h9 INTEGER NOT NULL, h10 INTEGER NOT NULL, h11 INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS target_activity_daily (date TEXT NOT NULL, target INTEGER NOT NULL CHECK(target BETWEEN 0 AND 4294967295), queries INTEGER NOT NULL, PRIMARY KEY(date,target));
CREATE TABLE IF NOT EXISTS kpi_daily (date TEXT PRIMARY KEY, active_targets INTEGER NOT NULL, active_prefixes INTEGER NOT NULL, tracking_complete INTEGER NOT NULL);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("metrics: migrate: %w", err)
	}
	for _, statement := range []string{
		`ALTER TABLE dns_hourly ADD COLUMN latency_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE dns_hourly ADD COLUMN latency_sum_us INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE dns_hourly ADD COLUMN latency_max_us INTEGER NOT NULL DEFAULT 0`,
	} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil && !isDuplicateColumn(err) {
			return fmt.Errorf("metrics: migrate: %w", err)
		}
	}
	return nil
}

func isDuplicateColumn(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column name")
}

func dateOf(t time.Time) string      { return t.UTC().Format("2006-01-02") }
func hourOf(t time.Time) time.Time   { return t.UTC().Truncate(time.Hour) }
func minuteOf(t time.Time) time.Time { return t.UTC().Truncate(time.Minute) }

func addrUint32(a netip.Addr) (uint32, bool) {
	if !a.Is4() {
		return 0, false
	}
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), true
}

func uint32Addr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func histIndex(d time.Duration) int {
	for i, bound := range LatencyBounds {
		if d <= bound {
			return i
		}
	}
	return histogramLen - 1
}

// RecordTarget records one valid target question without SQL or I/O.
func (s *Store) RecordTarget(target netip.Addr) {
	ip, ok := addrUint32(target)
	if !ok {
		return
	}
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
	if date != s.currentDate {
		s.currentDate, s.current = date, make(map[uint32]uint64)
	}
	if _, exists := s.current[ip]; !exists && len(s.current) >= targetLimit {
		s.dropped[date]++
		return
	}
	s.current[ip]++
	if s.pendingDaily[date] == nil {
		s.pendingDaily[date] = make(map[uint32]uint64)
	}
	s.pendingDaily[date][ip]++
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

func (s *Store) restore(ctx context.Context) error {
	now := s.cfg.now().UTC()
	date := dateOf(now)
	s.currentDate = date
	rows, err := s.db.QueryContext(ctx, `SELECT target,queries FROM target_activity_daily WHERE date=?`, date)
	if err != nil {
		return fmt.Errorf("metrics: restore: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ip int64
		var n uint64
		if err := rows.Scan(&ip, &n); err != nil {
			return err
		}
		s.current[uint32(ip)] = n
	}
	var complete int
	err = s.db.QueryRowContext(ctx, `SELECT tracking_complete FROM kpi_daily WHERE date=?`, date).Scan(&complete)
	if err == nil && complete == 0 {
		s.dropped[date] = 1
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return rows.Err()
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
	hours, days, dropped := s.pendingHourly, s.pendingDaily, s.dropped
	s.pendingHourly, s.pendingDaily, s.dropped = make(map[time.Time]aggregate), make(map[string]map[uint32]uint64), make(map[string]uint64)
	s.mu.Unlock()
	err := s.flushBatch(ctx, hours, days, dropped)
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
		for d, targets := range days {
			if s.pendingDaily[d] == nil {
				s.pendingDaily[d] = make(map[uint32]uint64)
			}
			for ip, n := range targets {
				s.pendingDaily[d][ip] += n
			}
		}
		for d, n := range dropped {
			s.dropped[d] += n
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

func (s *Store) flushBatch(ctx context.Context, hours map[time.Time]aggregate, days map[string]map[uint32]uint64, dropped map[string]uint64) error {
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
	for date, targets := range days {
		for ip, n := range targets {
			if _, err = tx.ExecContext(ctx, `INSERT INTO target_activity_daily(date,target,queries) VALUES(?,?,?) ON CONFLICT(date,target) DO UPDATE SET queries=queries+excluded.queries`, date, int64(ip), n); err != nil {
				return err
			}
		}
	}
	dates := unionDates(days, dropped)
	// Materialize a daily rolling snapshot even when the current day has no
	// new DNS observations. This keeps the historical KPI series continuous.
	dates[dateOf(s.cfg.now())] = struct{}{}
	for date := range dates {
		var targets, prefixes uint64
		if err = tx.QueryRowContext(ctx, `SELECT count(*),count(DISTINCT (target >> 8)) FROM target_activity_daily WHERE date BETWEEN date(?,'-29 days') AND ?`, date, date).Scan(&targets, &prefixes); err != nil {
			return err
		}
		complete := 1
		var incomplete int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM kpi_daily WHERE date BETWEEN date(?,'-29 days') AND ? AND tracking_complete=0`, date, date).Scan(&incomplete); err != nil {
			return err
		}
		if incomplete > 0 || dropped[date] > 0 {
			complete = 0
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO kpi_daily VALUES(?,?,?,?) ON CONFLICT(date) DO UPDATE SET active_targets=excluded.active_targets,active_prefixes=excluded.active_prefixes,tracking_complete=MIN(kpi_daily.tracking_complete,excluded.tracking_complete)`, date, targets, prefixes, complete); err != nil {
			return err
		}
	}
	cutoff := s.cfg.now().UTC().AddDate(0, 0, -34).Format("2006-01-02")
	if _, err = tx.ExecContext(ctx, `DELETE FROM target_activity_daily WHERE date < ?`, cutoff); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("metrics: flush: %w", err)
	}
	return nil
}

func unionDates(a map[string]map[uint32]uint64, b map[string]uint64) map[string]struct{} {
	r := make(map[string]struct{})
	for k := range a {
		r[k] = struct{}{}
	}
	for k := range b {
		r[k] = struct{}{}
	}
	return r
}

// RebuildSnapshot reads SQLite and recent RAM into a new snapshot.
func (s *Store) RebuildSnapshot(ctx context.Context) error {
	now := s.cfg.now().UTC()
	cutoff := now.Add(-23 * time.Hour).Truncate(time.Hour).Format(time.RFC3339)
	var out Snapshot
	out.FreshAt = now
	out.TrackingComplete = true
	var responseHist [histogramLen]uint64
	row := s.db.QueryRowContext(ctx, `SELECT COALESCE(sum(queries),0),COALESCE(sum(write_attempts),0),COALESCE(sum(write_successes),0),COALESCE(sum(h0),0),COALESCE(sum(h1),0),COALESCE(sum(h2),0),COALESCE(sum(h3),0),COALESCE(sum(h4),0),COALESCE(sum(h5),0),COALESCE(sum(h6),0),COALESCE(sum(h7),0),COALESCE(sum(h8),0),COALESCE(sum(h9),0),COALESCE(sum(h10),0),COALESCE(sum(h11),0) FROM dns_hourly WHERE hour>=?`, cutoff)
	if err := row.Scan(&out.Queries24H, &out.WriteAttempts24H, &out.WriteSuccesses24H, &responseHist[0], &responseHist[1], &responseHist[2], &responseHist[3], &responseHist[4], &responseHist[5], &responseHist[6], &responseHist[7], &responseHist[8], &responseHist[9], &responseHist[10], &responseHist[11]); err != nil {
		return s.snapshotError(err)
	}
	out.ResponseP95, out.ResponseP95Overflow = percentile95(responseHist)
	startDate, endDate := now.AddDate(0, 0, -29).Format("2006-01-02"), dateOf(now)
	dailyEnd := dateOf(now.AddDate(0, 0, 1)) + "T00:00:00Z"
	dailyRows, err := s.db.QueryContext(ctx, `SELECT substr(hour,1,10),sum(queries) FROM dns_hourly WHERE hour>=? AND hour<? GROUP BY substr(hour,1,10)`, startDate+"T00:00:00Z", dailyEnd)
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
	}
	rows, err := s.db.QueryContext(ctx, `SELECT target,sum(queries) FROM target_activity_daily WHERE date BETWEEN ? AND ? GROUP BY target`, startDate, endDate)
	if err != nil {
		return s.snapshotError(err)
	}
	var all []targetQuery
	for rows.Next() {
		var ip int64
		var q uint64
		if err = rows.Scan(&ip, &q); err != nil {
			rows.Close()
			return s.snapshotError(err)
		}
		all = append(all, targetQuery{uint32(ip), q})
	}
	err = rows.Close()
	if err != nil {
		return s.snapshotError(err)
	}
	var incomplete int
	if err = s.db.QueryRowContext(ctx, `SELECT count(*) FROM kpi_daily WHERE date BETWEEN ? AND ? AND tracking_complete=0`, startDate, endDate).Scan(&incomplete); err != nil {
		return s.snapshotError(err)
	}
	out.TrackingComplete = incomplete == 0
	s.mu.Lock()
	for date, count := range s.dropped {
		if count > 0 && date >= startDate && date <= endDate {
			out.TrackingComplete = false
		}
	}
	lastFlushAt, lastFlushErr := s.lastFlushAt, s.lastFlushErr
	s.mu.Unlock()
	if out.TrackingComplete {
		populateTargets(&out, all)
	} else {
		out.Degraded = true
		out.Error = "target tracking incomplete"
	}
	s.mu.Lock()
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
	applyReadiness(&out, s.readiness)
	s.snap = out
	s.snapMu.Unlock()
	return nil
}

// SetReadiness updates the current certificate readiness without touching the
// historical DNS aggregates.
func (s *Store) SetReadiness(readiness Readiness) {
	s.snapMu.Lock()
	previous := s.snap.Readiness
	s.readiness = readiness
	if previous.Degraded && s.snap.Error == previous.Error {
		s.snap.Error = ""
	}
	s.snap.Degraded = s.snap.Unavailable || !s.snap.TrackingComplete || s.snap.LastFlushError != "" || s.snap.Error != ""
	applyReadiness(&s.snap, readiness)
	s.snapMu.Unlock()
}

func applyReadiness(snapshot *Snapshot, readiness Readiness) {
	snapshot.Readiness = readiness
	if !readiness.Degraded {
		return
	}
	snapshot.Degraded = true
	if snapshot.Error == "" {
		snapshot.Error = readiness.Error
	}
}

func populateTargets(out *Snapshot, all []targetQuery) {
	blocks, prefixes, targets := make(map[string]uint64), make(map[string]uint64), make(map[string]uint64)
	for _, item := range all {
		addr := uint32Addr(item.ip)
		targets[addr.String()] += item.q
		prefixes[netip.PrefixFrom(addr, 24).Masked().String()] += item.q
		switch {
		case item.ip>>24 == 10:
			blocks["10.0.0.0/8"] += item.q
		case item.ip >= 0xac100000 && item.ip <= 0xac1fffff:
			blocks["172.16.0.0/12"] += item.q
		case item.ip>>16 == 0xc0a8:
			blocks["192.168.0.0/16"] += item.q
		}
	}
	out.ActiveTargets30D = uint64(len(all))
	out.ActivePrefixes30D = uint64(len(prefixes))
	out.TopBlocks, out.OtherBlockQueries = top20(blocks)
	out.TopPrefixes, out.OtherPrefixQueries = top20(prefixes)
	out.TopTargets, out.OtherTargetQueries = top20(targets)
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
	r.TopBlocks = append([]Breakdown(nil), r.TopBlocks...)
	r.TopPrefixes = append([]Breakdown(nil), r.TopPrefixes...)
	r.TopTargets = append([]Breakdown(nil), r.TopTargets...)
	r.DailyLookups = append([]DailyLookup(nil), r.DailyLookups...)
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

func top20(m map[string]uint64) ([]Breakdown, uint64) {
	r := make([]Breakdown, 0, len(m))
	for k, v := range m {
		r = append(r, Breakdown{k, v})
	}
	sort.Slice(r, func(i, j int) bool {
		if r[i].Queries == r[j].Queries {
			return r[i].Name < r[j].Name
		}
		return r[i].Queries > r[j].Queries
	})
	if len(r) > 20 {
		var other uint64
		for _, item := range r[20:] {
			other += item.Queries
		}
		r = r[:20]
		return r, other
	}
	return r, 0
}

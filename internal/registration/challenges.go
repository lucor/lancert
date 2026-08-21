package registration

import (
	"sync"
	"time"
)

const (
	maxChallenges            = 2
	challengeLifetime        = 15 * time.Minute
	challengeCleanupInterval = time.Minute
)

type challengeRecord struct {
	value     string
	expiresAt time.Time
}

// challengeStore keeps the short-lived DNS-01 state out of the persistent
// registration database. Values are ordered newest first.
type challengeStore struct {
	mu       sync.Mutex
	now      func() time.Time
	lifetime time.Duration
	records  map[string][]challengeRecord
	stop     chan struct{}
	done     chan struct{}
	close    sync.Once
}

func newChallengeStore(now func() time.Time, lifetime, cleanupInterval time.Duration) *challengeStore {
	s := &challengeStore{
		now:      now,
		lifetime: lifetime,
		records:  make(map[string][]challengeRecord),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go s.run(cleanupInterval)
	return s
}

func (s *challengeStore) Set(hostname, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	records := s.unexpired(s.records[hostname], now)
	updated := make([]challengeRecord, 0, maxChallenges)
	updated = append(updated, challengeRecord{value: value, expiresAt: now.Add(s.lifetime)})
	for _, record := range records {
		if record.value != value && len(updated) < maxChallenges {
			updated = append(updated, record)
		}
	}
	s.records[hostname] = updated
}

func (s *challengeStore) Lookup(hostname string) [maxChallenges]string {
	s.mu.Lock()
	defer s.mu.Unlock()

	records := s.unexpired(s.records[hostname], s.now())
	if len(records) == 0 {
		delete(s.records, hostname)
		return [maxChallenges]string{}
	}
	s.records[hostname] = records
	var values [maxChallenges]string
	for i, record := range records {
		values[i] = record.value
	}
	return values
}

func (s *challengeStore) unexpired(records []challengeRecord, now time.Time) []challengeRecord {
	active := records[:0]
	for _, record := range records {
		if now.Before(record.expiresAt) {
			active = append(active, record)
		}
	}
	return active
}

func (s *challengeStore) run(cleanupInterval time.Duration) {
	defer close(s.done)
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.purgeExpired()
		case <-s.stop:
			return
		}
	}
}

func (s *challengeStore) purgeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for hostname, records := range s.records {
		records = s.unexpired(records, now)
		if len(records) == 0 {
			delete(s.records, hostname)
			continue
		}
		s.records[hostname] = records
	}
}

func (s *challengeStore) Close() {
	s.close.Do(func() { close(s.stop) })
	<-s.done
}

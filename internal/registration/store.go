// Package registration owns persistent Lancert v2 registration state and its
// active, in-memory read view.
package registration

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.lucor.dev/lancert/internal/migrations"
	"go.lucor.dev/lancert/internal/privateip"
	"golang.org/x/crypto/blake2b"
	_ "modernc.org/sqlite"
)

const (
	operationTimeout      = 5 * time.Second
	maxHostnameAttempts   = 16
	plainHostnameAttempts = 4
)

var (
	// ErrForbidden deliberately covers every authentication and authorization
	// failure without revealing which check failed.
	ErrForbidden = errors.New("forbidden")
	// ErrInvalidChallenge indicates malformed TXT data after valid authentication.
	ErrInvalidChallenge = errors.New("invalid challenge")
	// ErrInvalidAddress indicates that registration was attempted for a non-RFC1918 IPv4 address.
	ErrInvalidAddress = errors.New("invalid private IPv4 address")
)

var dummyDigest = digestKey("dummy-key-never-issued")

// Option configures a Store.
type Option func(*config)

type config struct {
	random            io.Reader
	now               func() time.Time
	hostnameGenerator func(io.Reader, bool) (string, error)
}

// WithRandom sets the source used to generate IDs and credentials.
func WithRandom(r io.Reader) Option { return func(c *config) { c.random = r } }

// WithClock sets the clock used for persistence timestamps.
func WithClock(now func() time.Time) Option { return func(c *config) { c.now = now } }

// Credentials are returned exactly once when a registration is created.
type Credentials struct {
	ID       string
	Hostname string
	Username string
	Password string
}

// Registration is the active read view used by later DNS integration.
type Registration struct {
	ID         string
	Hostname   string
	TargetIP   netip.Addr
	Challenges [2]string // newest first; empty entries are omitted values
}

// Store serializes commits and publication to its active read view.
type Store struct {
	db                *sql.DB
	random            io.Reader
	now               func() time.Time
	hostnameGenerator func(io.Reader, bool) (string, error)
	challenges        *challengeStore

	mutationMu sync.Mutex
	viewMu     sync.RWMutex
	active     map[string]Registration
}

// Open opens, migrates, and loads essential registration state. Any failure is fatal.
func Open(path string, options ...Option) (*Store, error) {
	cfg := config{random: rand.Reader, now: time.Now, hostnameGenerator: generateHostname}
	for _, option := range options {
		option(&cfg)
	}
	if cfg.random == nil || cfg.now == nil || cfg.hostnameGenerator == nil {
		return nil, errors.New("registration: nil option")
	}

	if path != ":memory:" {
		parent := filepath.Dir(path)
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return nil, fmt.Errorf("registration: create state directory: %w", err)
		}
		if err := os.Chmod(parent, 0o700); err != nil {
			return nil, fmt.Errorf("registration: secure state directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("registration: open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	closeOnError := func(err error) (*Store, error) { _ = db.Close(); return nil, err }

	ctx, cancel := context.WithTimeout(context.Background(), operationTimeout)
	defer cancel()
	pragmas := []string{
		"PRAGMA busy_timeout=5000", // wait for a short-lived lock
		"PRAGMA synchronous=FULL",  // keep authoritative state durable
	}
	for _, pragma := range pragmas {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			return closeOnError(fmt.Errorf("registration: configure database: %w", err))
		}
	}
	if path != ":memory:" {
		var journalMode string
		if err := db.QueryRowContext(ctx, "PRAGMA journal_mode=DELETE").Scan(&journalMode); err != nil {
			return closeOnError(fmt.Errorf("registration: configure journal mode: %w", err))
		}
		if !strings.EqualFold(journalMode, "delete") {
			return closeOnError(fmt.Errorf("registration: configure journal mode: got %q, want delete", journalMode))
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return closeOnError(fmt.Errorf("registration: secure database: %w", err))
		}
	}
	if err := migrations.RunRegistration(db); err != nil {
		return closeOnError(fmt.Errorf("registration: migrate: %w", err))
	}

	s := &Store{
		db:                db,
		random:            cfg.random,
		now:               cfg.now,
		hostnameGenerator: cfg.hostnameGenerator,
		active:            make(map[string]Registration),
	}
	if err := s.validateState(ctx); err != nil {
		return closeOnError(err)
	}
	if err := s.load(ctx); err != nil {
		return closeOnError(err)
	}
	s.challenges = newChallengeStore(cfg.now, challengeLifetime, challengeCleanupInterval)
	return s, nil
}

func (s *Store) validateState(ctx context.Context) error {
	var integrity string
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&integrity); err != nil || integrity != "ok" {
		return fmt.Errorf("registration: database integrity check: got %q: %w", integrity, err)
	}
	var malformed int
	const query = `
SELECT count(*) FROM registrations r
WHERE typeof(r.api_key_digest) != 'blob'
   OR length(r.api_key_digest) != 32
   OR r.challenge_count < 0
   OR (r.challenge_count = 0 AND r.challenge_updated_at IS NOT NULL)
   OR (r.challenge_count > 0 AND r.challenge_updated_at IS NULL)`
	if err := s.db.QueryRowContext(ctx, query).Scan(&malformed); err != nil {
		return fmt.Errorf("registration: validate state: %w", err)
	}
	if malformed != 0 {
		return fmt.Errorf("registration: invalid persisted state for %d registration(s)", malformed)
	}
	return nil
}

func (s *Store) load(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id,hostname,target_ip FROM registrations WHERE status='active' ORDER BY id`)
	if err != nil {
		return fmt.Errorf("registration: load state: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, hostname string
		var targetIP string
		if err := rows.Scan(&id, &hostname, &targetIP); err != nil {
			return fmt.Errorf("registration: scan state: %w", err)
		}
		addr, err := privateip.ValidateRFC1918(targetIP)
		if err != nil || !validInternalID(id) || !validHostname(hostname) {
			return fmt.Errorf("registration: invalid active registration %q", id)
		}
		s.active[hostname] = Registration{ID: id, Hostname: hostname, TargetIP: addr}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("registration: load state: %w", err)
	}
	return nil
}

// Lookup returns a copy of an active registration's committed state.
func (s *Store) Lookup(hostname string) (Registration, bool) {
	s.viewMu.RLock()
	r, ok := s.active[hostname]
	s.viewMu.RUnlock()
	if ok {
		r.Challenges = s.challenges.Lookup(hostname)
	}
	return r, ok
}

// Register creates an RFC1918 registration.
func (s *Store) Register(ctx context.Context, addr netip.Addr) (Credentials, error) {
	if !addr.IsValid() || !addr.Is4() || !privateip.IsRFC1918(addr) {
		return Credentials{}, ErrInvalidAddress
	}
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	for attempt := 0; attempt < maxHostnameAttempts; attempt++ {
		credentials, digest, err := s.generateCredentials(attempt >= plainHostnameAttempts)
		if err != nil {
			return Credentials{}, err
		}
		operationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
		result, err := s.db.ExecContext(operationCtx, `INSERT INTO registrations(id,hostname,target_ip,api_username,api_key_digest,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(hostname) DO NOTHING`, credentials.ID, credentials.Hostname, addr.String(), credentials.Username, digest[:], s.now().Unix())
		if err != nil {
			cancel()
			return Credentials{}, fmt.Errorf("registration: persist registration: %w", err)
		}
		cancel()
		affected, err := result.RowsAffected()
		if err != nil {
			return Credentials{}, fmt.Errorf("registration: inspect registration: %w", err)
		}
		if affected == 0 {
			continue
		}
		s.viewMu.Lock()
		s.active[credentials.Hostname] = Registration{ID: credentials.ID, Hostname: credentials.Hostname, TargetIP: addr}
		s.viewMu.Unlock()
		return credentials, nil
	}
	return Credentials{}, errors.New("registration: hostname collision retry limit reached")
}

func (s *Store) generateCredentials(withHostnameSuffix bool) (Credentials, [32]byte, error) {
	read := func(n int) ([]byte, error) { b := make([]byte, n); _, err := io.ReadFull(s.random, b); return b, err }
	id, err := uuid.NewV7FromReader(s.random)
	if err != nil {
		return Credentials{}, [32]byte{}, fmt.Errorf("registration: generate ID: %w", err)
	}
	hostname, err := s.hostnameGenerator(s.random, withHostnameSuffix)
	if err != nil {
		return Credentials{}, [32]byte{}, fmt.Errorf("registration: generate hostname: %w", err)
	}
	username, err := uuid.NewRandomFromReader(s.random)
	if err != nil {
		return Credentials{}, [32]byte{}, fmt.Errorf("registration: generate username: %w", err)
	}
	passwordBytes, err := read(30)
	if err != nil {
		return Credentials{}, [32]byte{}, fmt.Errorf("registration: generate password: %w", err)
	}
	password := base64.RawURLEncoding.EncodeToString(passwordBytes)
	credentials := Credentials{ID: id.String(), Hostname: hostname, Username: username.String(), Password: password}
	return credentials, digestKey(password), nil
}

// UpdateChallenge authenticates, records usage, publishes an ephemeral
// challenge, and returns the owning registration ID.
func (s *Store) UpdateChallenge(ctx context.Context, username, key, subdomain, value string) (string, error) {
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	operationCtx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()

	var id, hostname, status string
	var stored []byte
	err := s.db.QueryRowContext(operationCtx, `SELECT id,hostname,api_key_digest,status FROM registrations WHERE api_username=?`, username).Scan(&id, &hostname, &stored, &status)
	presented := digestKey(key)
	if errors.Is(err, sql.ErrNoRows) {
		_ = subtle.ConstantTimeCompare(dummyDigest[:], presented[:])
		return "", ErrForbidden
	}
	if err != nil {
		return "", fmt.Errorf("registration: authenticate: %w", err)
	}
	validKey := subtle.ConstantTimeCompare(stored, presented[:]) == 1
	if !validKey || status != "active" || subdomain != hostname {
		return "", ErrForbidden
	}
	if !validChallenge(value) {
		return "", ErrInvalidChallenge
	}

	updatedAt := s.now().Unix()
	result, err := s.db.ExecContext(operationCtx, `UPDATE registrations SET challenge_count=challenge_count+1,challenge_updated_at=? WHERE id=?`, updatedAt, id)
	if err != nil {
		return "", fmt.Errorf("registration: record challenge: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("registration: inspect challenge record: %w", err)
	}
	if affected != 1 {
		return "", errors.New("registration: challenge registration disappeared")
	}
	s.challenges.Set(hostname, value)
	return id, nil
}

func validChallenge(value string) bool {
	if len(value) != 43 {
		return false
	}
	for i := range len(value) {
		c := value[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validInternalID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed.Version() == uuid.Version(7) && parsed.Variant() == uuid.RFC4122
}

func digestKey(key string) [32]byte {
	return blake2b.Sum256(append([]byte("lancert-v2-api-key\x00"), key...))
}

// Close stops ephemeral challenge cleanup and closes the state database.
func (s *Store) Close() error {
	s.challenges.Close()
	return s.db.Close()
}

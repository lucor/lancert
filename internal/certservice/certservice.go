// Package certservice orchestrates certificate lifecycle: issuance, renewal,
// caching, and rate limit protection.
//
// # Async issuance model
//
// ACME DNS-01 issuance takes up to 12 minutes (two serial authorizations, each
// with up to 5 minutes of propagation polling, plus finalization overhead).
// lancert is deployed behind a reverse proxy (Traefik/Dokploy) that has its own
// request timeout — blocking a POST for 12 minutes would cause the proxy to
// return a 504 to the client, leaving the cert on disk with no way to retrieve
// it through the normal response.
//
// To avoid this, the API is fire-and-forget: POST triggers background issuance
// and returns 202 immediately. The client polls GET until 200 (cert ready),
// a 5xx error (issuance failed), or it gives up. This decouples the HTTP
// request lifetime from the ACME flow entirely.
//
// # On-demand model
//
// There is no background renewal loop. Renewal is lazy: GetOrIssue checks the
// stored certificate on every call and re-issues if less than 30 days remain
// (renewThreshold). The renewal code path is identical to first-time issuance —
// a new ACME order is placed and a new keypair is generated. GetOrIssue is
// used internally by backgroundIssue and Pregen; it is not called directly
// by HTTP handlers.
//
// # Per-certificate keypair
//
// A fresh ECDSA P256 key is generated on every issuance, including renewals.
// The private key never leaves the server — it is generated locally, put into
// the CSR, and stored on disk alongside the signed certificate chain. Let's
// Encrypt signs the CSR but never sees or returns the private key.
// Generating a new key per renewal limits the blast radius of a compromise to
// the 90-day window of that certificate; past traffic encrypted with a previous
// key remains safe.
//
// # Background issuance
//
// backgroundIssue runs in a goroutine with context.Background() and a hard
// timeout (issuanceTimeout = 12 minutes). Using the request context would be
// wrong: the client may disconnect or the proxy may cancel the request long
// before the ACME flow completes, which would cancel the in-flight job and
// leave the issue map stuck in "pending" with no recovery path.
//
// singleflight deduplicates concurrent triggers for the same IP (e.g. Pregen
// and an API request racing at startup). Only one ACME call fires per IP
// regardless of how many goroutines request it simultaneously.
//
// # Failure tracking
//
// Failed issuance records are stored in the issues map with the HTTP status
// pre-classified by classifyIssueError. The status is stored at failure time
// rather than computed at response time so that the handler layer does not need
// to inspect error chains from another package — it reads an int directly.
//
// failureCooldown (1 hour) controls how long a failure record is surfaced
// before the IP can be retried. This prevents hammering Let's Encrypt after
// authorization failures; LE's own recommended retry delay for auth errors is
// in this range. Expired records are cleaned up lazily in GetStatus — the map
// holds at most one entry per recently-requested IP, so a background sweeper
// would add complexity with no practical benefit.
//
// # Issuance budget
//
// A rolling 7-day counter enforces a local limit (default 40) well below Let's
// Encrypt's 50 certificates/week/domain cap. BudgetExhausted is a read-only
// precheck used by handlers to reject requests early; the real atomic gate is
// budget.allow() inside issue(), which runs after singleflight deduplication.
// This means concurrent triggers for the same IP consume only one token, not
// one per caller.
//
// # Pre-generation
//
// Pregen issues certificates for a curated list of common private IPs at
// startup so that the first real request for those IPs is a cache hit. It runs
// once in a goroutine and is not a renewal scheduler — it does not run again
// after startup.
//
// # Storage
//
// Certificates are stored on disk (one directory per IP) and survive restarts.
// The store holds the private key PEM, the full certificate chain PEM, and a
// metadata file (domains, issuance date, expiry) used for renewal decisions and
// TTL queries.
package certservice

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/sync/singleflight"

	acmeissue "lucor.dev/lancert/internal/acme"
	"lucor.dev/lancert/internal/certstore"
	"lucor.dev/lancert/internal/dnssrv"
	"lucor.dev/lancert/internal/privateip"
)

const (
	// renewThreshold triggers renewal when cert has less than this remaining.
	renewThreshold = 30 * 24 * time.Hour

	// budgetWindow is the rolling window for the issuance budget.
	// Let's Encrypt allows ~50 new certs per registered domain per week.
	budgetWindow = 7 * 24 * time.Hour

	// defaultBudgetLimit is a safe default well below the LE limit of 50.
	defaultBudgetLimit = 40
)

// ErrBudgetExhausted is returned when the weekly issuance budget is spent.
var ErrBudgetExhausted = errors.New("weekly certificate issuance budget exhausted")

// Config holds the service configuration.
type Config struct {
	Zone        string
	Email       string
	AccountKey  *ecdsa.PrivateKey
	Staging     bool
	BudgetLimit int    // max new certs per budgetWindow; 0 = defaultBudgetLimit
	DataDir     string // directory for persisting budget state (e.g. "data")
}

// failRecord holds information about a failed issuance attempt.
type failRecord struct {
	err    error
	status int       // HTTP status code for the failure
	at     time.Time // when the failure occurred
}

// failureCooldown is how long a failure record is surfaced before expiring.
const failureCooldown = 1 * time.Hour

// issueRecord tracks in-progress or recently-failed issuance for an IP.
type issueRecord struct {
	pending bool
	fail    *failRecord // nil while pending or after success
}

// IssueStatus is the result of GetStatus — exactly one field is set.
type IssueStatus struct {
	Bundle  *certstore.CertBundle // non-nil: usable cert on disk
	Pending bool                  // issuance in progress
	Fail    *FailInfo             // non-nil: recent failure
}

// FailInfo exposes failure details to the handler layer.
type FailInfo struct {
	Status int    // HTTP status code
	Msg    string // error message
}

// Stats holds a point-in-time snapshot of service-level statistics.
type Stats struct {
	CertCount        int
	TotalIssued      int64
	BudgetUsed       int64
	BudgetLimit      int64
	BudgetResetsIn   time.Duration
	PendingIssuances int
	FailedIssuances  int
	Uptime           time.Duration
}

// issuanceTimeout is the context timeout for background issuance goroutines.
// ACME DNS-01 does 2 serial authorizations (bare + wildcard), each with up
// to 5 minutes of propagation polling, plus finalization overhead.
const issuanceTimeout = 12 * time.Minute

// Service orchestrates certificate issuance and caching.
type Service struct {
	config    Config
	store     *certstore.Store
	txtStore  dnssrv.TXTHandler
	sfGroup   singleflight.Group // deduplicates concurrent issuance for the same IP
	budget    *issuanceBudget
	startedAt time.Time

	mu     sync.Mutex
	issues map[string]*issueRecord
}

// New creates a certificate service. If cfg.DataDir is set, the issuance
// budget is loaded from disk so that restarts do not reset the LE rate
// limit counter.
func New(cfg Config, store *certstore.Store, txtStore dnssrv.TXTHandler) *Service {
	limit := cfg.BudgetLimit
	if limit == 0 {
		limit = defaultBudgetLimit
	}

	budget := &issuanceBudget{limit: int64(limit)}
	if cfg.DataDir != "" {
		budget.path = filepath.Join(cfg.DataDir, "budget.json")
		budget.load()
	}

	return &Service{
		config:    cfg,
		store:     store,
		txtStore:  txtStore,
		budget:    budget,
		startedAt: time.Now(),
		issues:    make(map[string]*issueRecord),
	}
}

// GetOrIssue returns an existing valid certificate or issues a new one.
// Concurrent requests for the same IP are deduplicated via singleflight.
func (s *Service) GetOrIssue(ctx context.Context, addr netip.Addr) (*certstore.CertBundle, error) {
	// Fast path: valid cert already on disk.
	bundle, err := s.store.Load(addr)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	if bundle != nil && time.Until(bundle.Meta.NotAfter) > renewThreshold {
		slog.Debug("certservice: cache hit", "addr", addr, "expires", bundle.Meta.NotAfter.Format(time.DateOnly))
		return bundle, nil
	}

	// Slow path: collapse concurrent issuance requests for the same IP into one.
	v, err, _ := s.sfGroup.Do(addr.String(), func() (any, error) {
		return s.issue(ctx, addr)
	})
	if err != nil {
		return nil, err
	}
	return v.(*certstore.CertBundle), nil
}

// issue performs the double-check, budget gate, ACME issuance, and disk write.
// Called exclusively from GetOrIssue inside the singleflight group.
func (s *Service) issue(ctx context.Context, addr netip.Addr) (*certstore.CertBundle, error) {
	// Double-check: a previous in-flight call may have just issued and stored.
	bundle, err := s.store.Load(addr)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	if bundle != nil && time.Until(bundle.Meta.NotAfter) > renewThreshold {
		slog.Debug("certservice: cache hit after dedup", "addr", addr)
		return bundle, nil
	}

	// Consume a budget token before issuing. Checked here rather than before
	// the double-check so that concurrent waiters for the same IP do not each
	// burn a token — only the one that actually issues does.
	if !s.budget.allow() {
		slog.Warn("certservice: budget exhausted", "resets_in", s.budget.resetIn().Round(time.Minute))
		return nil, ErrBudgetExhausted
	}

	domains := privateip.Domains(addr, s.config.Zone)
	slog.Info("certservice: issuing cert", "addr", addr, "domains", domains)

	result, err := acmeissue.Issue(ctx, acmeissue.Request{
		Domains:    domains[:],
		Email:      s.config.Email,
		AccountKey: s.config.AccountKey,
		Staging:    s.config.Staging,
		TXTStore:   s.txtStore,
		Resolver:   nil, // system default; follows NS delegation to our authoritative DNS
	})
	if err != nil {
		return nil, fmt.Errorf("issue cert for %s: %w", addr, err)
	}

	if err := s.store.Save(addr, result.PrivKeyPEM, result.CertChainDER); err != nil {
		return nil, fmt.Errorf("store cert for %s: %w", addr, err)
	}

	slog.Info("certservice: cert issued and stored", "addr", addr)

	return s.store.Load(addr)
}

// TTL returns the remaining validity for the given IP.
func (s *Service) TTL(addr netip.Addr) time.Duration {
	return s.store.TTL(addr)
}

// CertCount returns the total number of stored certificates.
func (s *Service) CertCount() int {
	return s.store.Count()
}

// Stats returns a snapshot of service-level statistics. Budget and issue
// counters are collected under their respective locks; the returned values
// are a consistent point-in-time view per field group but not globally atomic.
func (s *Service) Stats() Stats {
	budgetUsed, budgetLimit, totalIssued, budgetResetsIn := s.budget.stats()

	s.mu.Lock()
	var pending, failed int
	for _, rec := range s.issues {
		switch {
		case rec.pending:
			pending++
		case rec.fail != nil:
			failed++
		}
	}
	s.mu.Unlock()

	return Stats{
		CertCount:        s.store.Count(),
		TotalIssued:      totalIssued,
		BudgetUsed:       budgetUsed,
		BudgetLimit:      budgetLimit,
		BudgetResetsIn:   budgetResetsIn,
		PendingIssuances: pending,
		FailedIssuances:  failed,
		Uptime:           time.Since(s.startedAt),
	}
}

// LoadUsable returns the stored certificate only if it is usable
// (i.e. has more than renewThreshold remaining). Returns nil, nil
// if no certificate exists or it needs renewal.
func (s *Service) LoadUsable(addr netip.Addr) (*certstore.CertBundle, error) {
	bundle, err := s.store.Load(addr)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	if bundle != nil && time.Until(bundle.Meta.NotAfter) > renewThreshold {
		return bundle, nil
	}
	return nil, nil
}

// BudgetExhausted returns true if the issuance budget is spent without
// consuming a token. Used by handlers for a quick precheck.
func (s *Service) BudgetExhausted() bool {
	return s.budget.exhausted()
}

// TriggerIssuance starts a background issuance goroutine for addr if one
// is not already pending and there is no recent failure in cooldown.
// Returns the current IssueStatus so the caller can respond immediately.
func (s *Service) TriggerIssuance(addr netip.Addr) IssueStatus {
	key := addr.String()

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.issues[key]
	if ok {
		if rec.pending {
			return IssueStatus{Pending: true}
		}
		// Existing failure record — check if still in cooldown.
		if rec.fail != nil && time.Since(rec.fail.at) < failureCooldown {
			return IssueStatus{Fail: &FailInfo{Status: rec.fail.status, Msg: rec.fail.err.Error()}}
		}
		// Expired failure — fall through to re-trigger.
	}

	// Mark pending and launch background goroutine.
	s.issues[key] = &issueRecord{pending: true}

	go s.backgroundIssue(addr, key)

	return IssueStatus{Pending: true}
}

// GetStatus returns the current state for addr: usable cert, pending, or failure.
func (s *Service) GetStatus(addr netip.Addr) (IssueStatus, error) {
	// Check disk for a usable cert first.
	bundle, err := s.LoadUsable(addr)
	if err != nil {
		return IssueStatus{}, err
	}
	if bundle != nil {
		return IssueStatus{Bundle: bundle}, nil
	}

	key := addr.String()
	s.mu.Lock()
	rec, ok := s.issues[key]
	s.mu.Unlock()

	if !ok {
		return IssueStatus{}, nil // never requested
	}

	if rec.pending {
		return IssueStatus{Pending: true}, nil
	}

	if rec.fail != nil {
		// Lazy expiry: if cooldown elapsed, treat as never-requested.
		if time.Since(rec.fail.at) >= failureCooldown {
			s.mu.Lock()
			delete(s.issues, key)
			s.mu.Unlock()
			return IssueStatus{}, nil
		}
		return IssueStatus{Fail: &FailInfo{Status: rec.fail.status, Msg: rec.fail.err.Error()}}, nil
	}

	return IssueStatus{}, nil
}

// backgroundIssue runs the ACME issuance flow in its own goroutine with an
// independent context. On success it deletes the issue record (the cert is on
// disk). On failure it stores a failRecord for the cooldown period.
func (s *Service) backgroundIssue(addr netip.Addr, key string) {
	ctx, cancel := context.WithTimeout(context.Background(), issuanceTimeout)
	defer cancel()

	// Use singleflight so that concurrent triggers (e.g. pregen + API) share
	// the same in-flight ACME call.
	v, err, _ := s.sfGroup.Do(key, func() (any, error) {
		return s.issue(ctx, addr)
	})

	s.mu.Lock()
	defer s.mu.Unlock()

	if err != nil {
		slog.Error("certservice: background issue failed", "addr", addr, "error", err)
		s.issues[key] = &issueRecord{
			fail: &failRecord{
				err:    err,
				status: classifyIssueError(err),
				at:     time.Now(),
			},
		}
		return
	}

	_ = v // cert is on disk, accessible via LoadUsable
	slog.Info("certservice: background issue succeeded", "addr", addr)
	delete(s.issues, key)
}

// classifyIssueError maps an issuance error to an HTTP status code.
func classifyIssueError(err error) int {
	if errors.Is(err, ErrBudgetExhausted) {
		return http.StatusServiceUnavailable // 503
	}
	if errors.Is(err, acmeissue.ErrPropagationTimeout) {
		return http.StatusGatewayTimeout // 504
	}
	var authErr *acme.AuthorizationError
	if errors.As(err, &authErr) {
		return http.StatusBadGateway // 502
	}
	return http.StatusInternalServerError // 500
}

// issuanceBudget tracks how many new certificates have been issued in the
// current rolling window. Protects the Let's Encrypt rate limit regardless
// of how many source IPs hit the API. When path is set, the counter is
// persisted to disk so that restarts do not reset it.
type issuanceBudget struct {
	mu          sync.Mutex
	limit       int64
	count       int64
	totalIssued int64
	windowStart int64  // unix seconds
	path        string // file path for persistence; empty = in-memory only
}

// budgetState is the JSON-serializable form of the budget counter.
type budgetState struct {
	Count       int64 `json:"count"`
	WindowStart int64 `json:"window_start"`
	TotalIssued int64 `json:"total_issued"`
}

// load restores the budget from disk. Errors are logged and ignored —
// a missing or corrupt file simply starts a fresh window.
func (b *issuanceBudget) load() {
	if b.path == "" {
		return
	}
	data, err := os.ReadFile(b.path)
	if err != nil {
		return
	}
	var s budgetState
	if err := json.Unmarshal(data, &s); err != nil {
		slog.Warn("budget: ignoring corrupt state file", "path", b.path, "error", err)
		return
	}
	// Lifetime counter always survives restarts.
	b.totalIssued = s.TotalIssued

	// Only restore the rolling window if it has not expired.
	if time.Now().Unix()-s.WindowStart <= int64(budgetWindow.Seconds()) {
		b.count = s.Count
		b.windowStart = s.WindowStart
		slog.Info("budget: restored from disk", "count", b.count, "window_start", time.Unix(b.windowStart, 0).Format(time.RFC3339))
	}
}

// save persists the current budget state to disk. Best-effort.
func (b *issuanceBudget) save() {
	if b.path == "" {
		return
	}
	data, _ := json.Marshal(budgetState{Count: b.count, WindowStart: b.windowStart, TotalIssued: b.totalIssued})
	if err := os.WriteFile(b.path, data, 0o600); err != nil {
		slog.Warn("budget: failed to persist state", "path", b.path, "error", err)
	}
}

// exhausted returns true if the budget is spent, without consuming a token.
func (b *issuanceBudget) exhausted() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now().Unix()
	if now-b.windowStart > int64(budgetWindow.Seconds()) {
		return false // window expired, budget has reset
	}
	return b.count >= b.limit
}

// allow checks whether an issuance is permitted. Returns false if the
// budget is exhausted. Increments the counter on success and persists to disk.
func (b *issuanceBudget) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now().Unix()

	// Reset window if expired
	if now-b.windowStart > int64(budgetWindow.Seconds()) {
		b.windowStart = now
		b.count = 1
		b.totalIssued++
		b.save()
		return true
	}

	if b.count >= b.limit {
		return false
	}

	b.count++
	b.totalIssued++
	b.save()
	return true
}

// stats returns the current budget count, limit, time until reset, and
// lifetime total under a single lock acquisition.
func (b *issuanceBudget) stats() (used, limit, totalIssued int64, resetsIn time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now().Unix()
	if now-b.windowStart > int64(budgetWindow.Seconds()) {
		return 0, b.limit, b.totalIssued, 0
	}

	end := time.Unix(b.windowStart, 0).Add(budgetWindow)
	remaining := time.Until(end)
	if remaining < 0 {
		remaining = 0
	}
	return b.count, b.limit, b.totalIssued, remaining
}

// resetIn returns the duration until the current budget window resets.
func (b *issuanceBudget) resetIn() time.Duration {
	b.mu.Lock()
	start := b.windowStart
	b.mu.Unlock()

	if start == 0 {
		return 0
	}

	end := time.Unix(start, 0).Add(budgetWindow)
	remaining := time.Until(end)
	if remaining < 0 {
		return 0
	}

	return remaining
}

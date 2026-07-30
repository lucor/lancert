// Package certservice orchestrates certificate lifecycle: issuance, renewal,
// caching, and rate limit protection.
//
// # Async issuance model
//
// ACME DNS-01 issuance can take several minutes (two serial authorizations,
// each with up to 5 minutes of propagation polling, plus finalization
// overhead). HTTP clients or intermediaries may enforce a shorter request
// timeout, so blocking a POST for the entire ACME flow is not reliable.
//
// To avoid this, the API is fire-and-forget: POST triggers background issuance
// and returns 202 immediately. The client polls GET until 200 (cert ready),
// a 5xx error (issuance failed), or it gives up. This decouples the HTTP
// request lifetime from the ACME flow entirely.
//
// # On-demand and ARI model
//
// On-demand issuance happens only when a certificate is absent or expired.
// Unexpired certificates remain servable through NotAfter. A single lifecycle
// worker handles ARI scheduling and performs replacements with replaces set to
// the current leaf certificate ID. RenewalWindow is used only as the fallback
// scheduling interval, not as a serving cutoff.
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
// backgroundIssue runs in a goroutine with an independent hard timeout
// (issuanceTimeout = 12 minutes). Using the request context would be wrong:
// the client may disconnect or the proxy may cancel the request long before
// the ACME flow completes.
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
// Each current certificate is an atomic versioned bundle containing the key,
// chain, certificate metadata, and ARI scheduling state. Legacy three-file
// directories are migrated eagerly at startup.
package certservice

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	ariacme "github.com/mholt/acmez/v3/acme"
	"golang.org/x/sync/singleflight"

	acmeissue "lucor.dev/lancert/internal/acme"
	"lucor.dev/lancert/internal/certstore"
	"lucor.dev/lancert/internal/dnssrv"
	"lucor.dev/lancert/internal/metrics"
	"lucor.dev/lancert/internal/privateip"
)

const (
	// RenewalWindow triggers renewal when a certificate has less than this
	// remaining. Certificates inside this window remain servable while renewal
	// proceeds in the background.
	RenewalWindow = 30 * 24 * time.Hour
)

// ErrSuspended reports that certificate operations are temporarily disabled.
var ErrSuspended = errors.New("certificate issuance and renewal are suspended")

// Config holds the service configuration.
type Config struct {
	Zone        string
	Email       string
	AccountKey  *ecdsa.PrivateKey
	Environment acmeissue.Environment
	CACertPath  string
	Resolver    *net.Resolver
	Suspended   bool
}

// failRecord holds information about a failed issuance attempt.
type failRecord struct {
	err        error
	status     int           // HTTP status code for the failure
	at         time.Time     // when the failure occurred
	retryAfter time.Duration // upstream retry delay, when available
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
	Bundle      *certstore.CertBundle // non-nil: usable cert on disk
	Pending     bool                  // issuance in progress
	RateLimited bool                  // a new issuance was denied by local admission
	Suspended   bool                  // certificate operations are disabled
	Fail        *FailInfo             // non-nil: recent failure
}

// FailInfo exposes failure details to the handler layer.
type FailInfo struct {
	Status     int           // HTTP status code
	Msg        string        // error message
	RetryAfter time.Duration // retry delay, when available
}

// issuanceTimeout is the context timeout for background issuance goroutines.
// ACME DNS-01 does 2 serial authorizations (bare + wildcard), each with up
// to 5 minutes of propagation polling, plus finalization overhead.
const issuanceTimeout = 12 * time.Minute

// Service orchestrates certificate issuance and caching.
type Service struct {
	config           Config
	store            *certstore.Store
	txtStore         dnssrv.TXTHandler
	metrics          metrics.Recorder
	issueCertificate func(context.Context, acmeissue.Request) (*acmeissue.Result, error)
	getRenewalInfo   func(context.Context, *x509.Certificate, acmeissue.Environment, string) (acmeissue.RenewalInfo, error)
	sfGroup          singleflight.Group // deduplicates concurrent issuance for the same IP

	mu     sync.Mutex
	issues map[string]*issueRecord
}

// New creates a certificate service.
func New(cfg Config, store *certstore.Store, txtStore dnssrv.TXTHandler, recorder metrics.Recorder) *Service {
	if cfg.Environment == "" {
		cfg.Environment = acmeissue.EnvironmentProduction
	}
	return &Service{
		config:           cfg,
		store:            store,
		txtStore:         txtStore,
		metrics:          recorder,
		issueCertificate: acmeissue.Issue,
		getRenewalInfo:   acmeissue.GetRenewalInfo,
		issues:           make(map[string]*issueRecord),
	}
}

// Suspended reports whether certificate issuance, renewal, and distribution
// should be disabled by callers.
func (s *Service) Suspended() bool {
	return s.config.Suspended
}

// GetOrIssue returns an existing valid certificate or issues a new one.
// Concurrent requests for the same IP are deduplicated via singleflight.
func (s *Service) GetOrIssue(ctx context.Context, addr netip.Addr) (*certstore.CertBundle, error) {
	if s.Suspended() {
		return nil, ErrSuspended
	}

	// Fast path: valid cert already on disk.
	bundle, err := s.store.Load(addr)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	if bundle != nil && time.Until(bundle.Meta.NotAfter) > 0 {
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

// issue performs the double-check, ACME issuance, and disk write.
// Called exclusively from GetOrIssue inside the singleflight group.
func (s *Service) issue(ctx context.Context, addr netip.Addr) (*certstore.CertBundle, error) {
	if s.Suspended() {
		return nil, ErrSuspended
	}

	// Double-check: a previous in-flight call may have just issued and stored.
	bundle, err := s.store.Load(addr)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	if bundle != nil && time.Until(bundle.Meta.NotAfter) > 0 {
		slog.Debug("certservice: cache hit after dedup", "addr", addr)
		return bundle, nil
	}
	previous := bundle != nil

	domains := privateip.Domains(addr, s.config.Zone)
	slog.Info("certservice: issuing cert", "addr", addr, "domains", domains)

	result, err := s.issueCertificate(ctx, acmeissue.Request{
		Domains:     domains[:],
		Email:       s.config.Email,
		AccountKey:  s.config.AccountKey,
		TXTStore:    s.txtStore,
		Resolver:    s.config.Resolver,
		Environment: s.config.Environment,
		CACertPath:  s.config.CACertPath,
	})
	if err != nil {
		return nil, fmt.Errorf("issue cert for %s: %w", addr, err)
	}

	if err := s.store.Save(addr, result.PrivKeyPEM, result.CertChainDER); err != nil {
		return nil, fmt.Errorf("store cert for %s: %w", addr, err)
	}

	slog.Info("certservice: cert issued and stored", "addr", addr)

	fresh, err := s.store.Load(addr)
	if err != nil {
		return nil, err
	}
	if fresh == nil {
		return nil, fmt.Errorf("stored cert for %s could not be reloaded", addr)
	}
	var recordErr error
	if previous {
		recordErr = s.metrics.RecordRenewal(ctx, false)
	} else {
		recordErr = s.metrics.RecordInitialIssuance(ctx)
	}
	if recordErr != nil {
		slog.Warn("certservice: lifecycle metric unavailable", "addr", addr, "error", recordErr)
	}
	return fresh, nil
}

// TTL returns the remaining validity for the given IP.
// A zero duration with nil error means the certificate is absent or expired.
func (s *Service) TTL(addr netip.Addr) (time.Duration, error) {
	bundle, err := s.store.Load(addr)
	if err != nil {
		return 0, err
	}
	if bundle == nil {
		return 0, nil
	}
	ttl := time.Until(bundle.Meta.NotAfter)
	if ttl <= 0 {
		return 0, nil
	}
	return ttl, nil
}

// LoadUsable returns the current stored certificate while it is unexpired.
func (s *Service) LoadUsable(addr netip.Addr) (*certstore.CertBundle, error) {
	bundle, err := s.store.Load(addr)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	if bundle != nil && time.Until(bundle.Meta.NotAfter) > 0 {
		return bundle, nil
	}
	return nil, nil
}

// TriggerIssuance starts a background issuance goroutine for addr if one
// is not already pending and there is no recent failure in cooldown.
// Returns the current IssueStatus so the caller can respond immediately.
func (s *Service) TriggerIssuance(addr netip.Addr) IssueStatus {
	return s.TriggerIssuanceIf(addr, nil)
}

// TriggerIssuanceIf starts issuance only when admit permits new work. The
// callback runs after pending and failure checks, while the service lock is
// held, so duplicate requests do not consume admission tokens.
func (s *Service) TriggerIssuanceIf(addr netip.Addr, admit func() bool) IssueStatus {
	if s.Suspended() {
		return IssueStatus{Suspended: true}
	}

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
			return IssueStatus{Fail: &FailInfo{Status: rec.fail.status, Msg: rec.fail.err.Error(), RetryAfter: rec.fail.retryAfter}}
		}
		// Expired failure — fall through to re-trigger.
	}
	if admit != nil && !admit() {
		return IssueStatus{RateLimited: true}
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
		return IssueStatus{Fail: &FailInfo{Status: rec.fail.status, Msg: rec.fail.err.Error(), RetryAfter: rec.fail.retryAfter}}, nil
	}

	return IssueStatus{}, nil
}

// backgroundIssue runs the ACME issuance flow in its own goroutine with an
// independent context. On success it deletes the issue record (the cert is on
// disk). On failure it stores a failRecord for the cooldown period.
func (s *Service) backgroundIssue(addr netip.Addr, key string) {
	if s.Suspended() {
		return
	}

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
				err:        err,
				status:     classifyIssueError(err),
				at:         time.Now().UTC(),
				retryAfter: retryAfter(err),
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
	if errors.Is(err, acmeissue.ErrRateLimited) {
		return http.StatusServiceUnavailable
	}
	if errors.Is(err, acmeissue.ErrPropagationTimeout) {
		return http.StatusGatewayTimeout // 504
	}
	var problem ariacme.Problem
	if errors.As(err, &problem) {
		// ACME authorization and identifier failures are upstream validation
		// failures, not Lancert server faults.
		if (problem.Status >= http.StatusBadRequest && problem.Status < http.StatusInternalServerError) ||
			problem.Type == ariacme.ProblemTypeUnauthorized ||
			problem.Type == ariacme.ProblemTypeMalformed ||
			problem.Type == ariacme.ProblemTypeRejectedIdentifier {
			return http.StatusBadGateway // 502
		}
	}
	return http.StatusInternalServerError // 500
}

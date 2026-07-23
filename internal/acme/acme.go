// Package acme performs ACME DNS-01 certificate issuance against the selected
// production, staging, or local Pebble authority.
//
// DNS-01 is the only challenge type used here because lancert issues certificates
// for RFC 1918 private IPs. Those addresses are unreachable from the public
// internet, making HTTP-01 and TLS-ALPN-01 impossible — LE's validators cannot
// reach them. DNS-01 works because lancert is itself the authoritative nameserver
// for the zone, so it can provision TXT records without any external dependency.
//
// Issuance and renewal flow:
//
//	Register / lookup account by key
//	└─ NewOrder (one order, N domains, optional ARI replaces)
//	   └─ for each domain authorization:
//	      ├─ SetTXT(_acme-challenge.<domain>)   ← in-memory DNS store
//	      ├─ waitForPropagation                 ← poll until TXT visible
//	      ├─ Initiate challenge                 ← notify LE to validate
//	      └─ Poll authorization                 ← poll until authz valid
//	   GenerateKey (P256) + CSR
//	   FinalizeOrder                            ← order → "valid"
//	   GetCertificateChain                      ← download the chain
//	   defer: cleanup TXT records
package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	ariacme "github.com/mholt/acmez/v3/acme"

	"lucor.dev/lancert/internal/dnssrv"
)

// ErrPropagationTimeout indicates that the DNS TXT record did not become
// visible within the propagation timeout window.
var ErrPropagationTimeout = errors.New("DNS propagation timeout")

// ErrRateLimited identifies an ACME rate-limit response.
var ErrRateLimited = errors.New("ACME rate limit exceeded")

// ErrAlreadyReplaced identifies a predecessor that the CA already replaced.
var ErrAlreadyReplaced = errors.New("ACME certificate already replaced")

// RateLimitError preserves the absolute time supplied by Retry-After.
type RateLimitError struct {
	Err     error
	RetryAt time.Time
}

// Error returns the underlying ACME problem text.
func (e *RateLimitError) Error() string { return e.Err.Error() }

// Unwrap exposes the underlying ACME problem for errors.Is and errors.As.
func (e *RateLimitError) Unwrap() error { return e.Err }

// RetryAfterDuration returns the remaining upstream retry delay.
func (e *RateLimitError) RetryAfterDuration() time.Duration {
	return max(time.Until(e.RetryAt), 0)
}

// RetryAfterTime returns the absolute upstream retry time.
func (e *RateLimitError) RetryAfterTime() time.Time { return e.RetryAt }

type retryCaptureTransport struct {
	base    http.RoundTripper
	mu      sync.Mutex
	retryAt time.Time
}

// RoundTrip records an absolute Retry-After instant while forwarding req.
func (t *retryCaptureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if resp != nil {
		var retryAt time.Time
		if value := resp.Header.Get("Retry-After"); value != "" {
			if seconds, parseErr := strconv.Atoi(value); parseErr == nil {
				retryAt = time.Now().Add(time.Duration(seconds) * time.Second)
			} else if when, parseErr := http.ParseTime(value); parseErr == nil {
				retryAt = when
			}
		}
		if !retryAt.After(time.Now()) {
			retryAt = time.Time{}
		}
		t.mu.Lock()
		t.retryAt = retryAt.UTC()
		t.mu.Unlock()
	}
	return resp, err
}

// reset clears Retry-After state before an operation that may be rate limited.
func (t *retryCaptureTransport) reset() {
	t.mu.Lock()
	t.retryAt = time.Time{}
	t.mu.Unlock()
}

// retryAfterTime returns the most recently observed Retry-After instant.
func (t *retryCaptureTransport) retryAfterTime() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.retryAt
}

const (
	// acmeHTTPTimeout bounds one HTTP exchange. The operation context still
	// controls the larger issuance or renewal workflow.
	acmeHTTPTimeout = 30 * time.Second

	letsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	letsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// txtRecordTTL is the TTL advertised for _acme-challenge TXT records.
	// 120s is short enough that stale records don't linger after cleanup,
	// but LE's resolvers still cache within this window — going lower
	// risks the record not being visible when LE validates.
	txtRecordTTL = 120 * time.Second

	// propagationTimeout caps how long we poll for DNS propagation before
	// giving up. LE's own challenge validation timeout is roughly 5 minutes;
	// we must confirm the TXT record is visible before calling Accept, or
	// the challenge fails permanently with no retry on the same order.
	propagationTimeout = 5 * time.Minute

	// propagationDelay is the interval between DNS lookup attempts.
	// 5s balances issuance latency against poll rate on our own DNS server.
	propagationDelay = 5 * time.Second

	// cleanupTimeout is the budget for removing TXT records after issuance.
	// A separate context is used because the parent context may already be
	// cancelled (request timeout, shutdown signal) by the time cleanup runs.
	// Stale _acme-challenge records would otherwise poison future challenge flows.
	cleanupTimeout = 30 * time.Second
)

// Environment selects the ACME authority used by lancert.
type Environment string

const (
	EnvironmentProduction Environment = "production"
	EnvironmentStaging    Environment = "staging"
	EnvironmentLocal      Environment = "local"
)

// directoryFor returns the directory endpoint for env.
func directoryFor(env Environment) (string, error) {
	if env == "" {
		env = EnvironmentProduction
	}
	switch env {
	case EnvironmentProduction:
		return letsEncryptProduction, nil
	case EnvironmentStaging:
		return letsEncryptStaging, nil
	case EnvironmentLocal:
		return PebbleDirectoryURL, nil
	default:
		return "", fmt.Errorf("invalid ACME environment %q", env)
	}
}

// httpClientFor builds the authority-specific HTTP client and optional
// Retry-After capture transport.
func httpClientFor(env Environment, caPath string, captureRetry bool) (*http.Client, *retryCaptureTransport, error) {
	base := http.DefaultTransport
	if env == EnvironmentLocal {
		client, err := localHTTPClient(caPath)
		if err != nil {
			return nil, nil, err
		}
		base = client.Transport
	}
	if !captureRetry {
		return &http.Client{Transport: base, Timeout: acmeHTTPTimeout}, nil, nil
	}
	transport := &retryCaptureTransport{base: base}
	return &http.Client{Transport: transport, Timeout: acmeHTTPTimeout}, transport, nil
}

// Request holds the parameters for certificate issuance.
type Request struct {
	Domains     []string
	Email       string
	AccountKey  *ecdsa.PrivateKey
	Environment Environment
	CACertPath  string
	TXTStore    dnssrv.TXTHandler
	// Resolver is the DNS resolver used to confirm TXT propagation.
	// nil uses the system default, which queries our authoritative DNS.
	// Tests can inject a resolver pointing at the in-process DNS server
	// to verify that TXT records are actually being served.
	Resolver *net.Resolver
	Replaces *x509.Certificate
}

// Result holds the issued certificate data.
type Result struct {
	PrivKeyPEM   []byte
	CertChainDER [][]byte
}

// RenewalInfo is the small internal representation of ACME ARI data.
type RenewalInfo struct {
	WindowStart time.Time
	WindowEnd   time.Time
	RetryAfter  time.Time
}

// GetRenewalInfo fetches ARI for a currently stored leaf certificate.
func GetRenewalInfo(ctx context.Context, leaf *x509.Certificate, env Environment, caPath string) (RenewalInfo, error) {
	if leaf == nil {
		return RenewalInfo{}, fmt.Errorf("leaf certificate is required")
	}
	directoryURL, err := directoryFor(env)
	if err != nil {
		return RenewalInfo{}, err
	}
	httpClient, _, err := httpClientFor(env, caPath, false)
	if err != nil {
		return RenewalInfo{}, err
	}
	client := &ariacme.Client{Directory: directoryURL, HTTPClient: httpClient}
	info, err := client.GetRenewalInfo(ctx, leaf)
	if err != nil {
		return RenewalInfo{}, err
	}
	return RenewalInfo{
		WindowStart: info.SuggestedWindow.Start,
		WindowEnd:   info.SuggestedWindow.End,
		RetryAfter:  derefTime(info.RetryAfter),
	}, nil
}

// derefTime normalizes an optional ACME timestamp to UTC.
func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}

// Issue performs the ACME DNS-01 flow using the low-level ARI-capable client.
func Issue(ctx context.Context, req Request) (*Result, error) {
	if len(req.Domains) == 0 {
		return nil, fmt.Errorf("at least one domain is required")
	}
	if req.AccountKey == nil {
		return nil, fmt.Errorf("ACME account key is required")
	}
	if req.TXTStore == nil {
		return nil, fmt.Errorf("DNS TXT store is required")
	}
	return issueLowLevel(ctx, req)
}

// issueLowLevel performs issuance with the ARI-capable low-level ACME client.
func issueLowLevel(ctx context.Context, req Request) (*Result, error) {
	directoryURL, err := directoryFor(req.Environment)
	if err != nil {
		return nil, err
	}
	httpClient, transport, err := httpClientFor(req.Environment, req.CACertPath, true)
	if err != nil {
		return nil, err
	}
	client := &ariacme.Client{Directory: directoryURL, HTTPClient: httpClient}
	account := ariacme.Account{PrivateKey: req.AccountKey, TermsOfServiceAgreed: true}
	if req.Email != "" {
		account.Contact = []string{"mailto:" + req.Email}
	}
	// NewAccount is idempotent for an account key: the CA returns the existing
	// account when the key is already registered. A separate GetAccount fallback
	// is incorrect here because it sends onlyReturnExisting and hides the real
	// registration error (especially with a freshly started Pebble instance).
	registered, err := client.NewAccount(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("register or load ACME account: %w", err)
	}
	account = registered
	ids := make([]ariacme.Identifier, 0, len(req.Domains))
	for _, domain := range req.Domains {
		ids = append(ids, ariacme.Identifier{Type: "dns", Value: domain})
	}
	order := ariacme.Order{Identifiers: ids}
	if req.Replaces != nil {
		order.Replaces, err = ariacme.ARIUniqueIdentifier(req.Replaces)
		if err != nil {
			return nil, fmt.Errorf("derive predecessor certificate ID: %w", err)
		}
	}
	transport.reset()
	order, err = client.NewOrder(ctx, account, order)
	if err != nil {
		var problem ariacme.Problem
		if errors.As(err, &problem) {
			if problem.Type == ariacme.ProblemTypeRateLimited {
				return nil, &RateLimitError{Err: fmt.Errorf("%w: %v", ErrRateLimited, err), RetryAt: transport.retryAfterTime()}
			}
			if problem.Type == ariacme.ProblemTypeAlreadyReplaced {
				return nil, fmt.Errorf("%w: %v", ErrAlreadyReplaced, err)
			}
		}
		return nil, fmt.Errorf("create ACME order: %w", err)
	}
	solver := &dnsSolver{store: req.TXTStore, resolver: req.Resolver, cleanups: make(map[string][]dnssrv.CleanupFunc)}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		solver.cleanupAll(cleanupCtx)
	}()
	for _, authzURL := range order.Authorizations {
		authz, err := client.GetAuthorization(ctx, account, authzURL)
		if err != nil {
			return nil, fmt.Errorf("get authorization: %w", err)
		}
		if authz.Status == ariacme.StatusValid {
			continue
		}
		var challenge *ariacme.Challenge
		for i := range authz.Challenges {
			if authz.Challenges[i].Type == ariacme.ChallengeTypeDNS01 {
				challenge = &authz.Challenges[i]
				break
			}
		}
		if challenge == nil {
			return nil, fmt.Errorf("no DNS-01 challenge for %s", authz.IdentifierValue())
		}
		if err := solver.Present(ctx, *challenge); err != nil {
			return nil, fmt.Errorf("present DNS challenge: %w", err)
		}
		if err := solver.Wait(ctx, *challenge); err != nil {
			return nil, fmt.Errorf("wait for DNS challenge: %w", err)
		}
		if _, err := client.InitiateChallenge(ctx, account, *challenge); err != nil {
			return nil, fmt.Errorf("initiate DNS challenge: %w", err)
		}
		if _, err := client.PollAuthorization(ctx, account, authz); err != nil {
			return nil, fmt.Errorf("poll authorization: %w", err)
		}
	}
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate certificate key: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: req.Domains[0]}, DNSNames: req.Domains}, certKey)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	order, err = client.FinalizeOrder(ctx, account, order, csr)
	if err != nil {
		return nil, fmt.Errorf("finalize ACME order: %w", err)
	}
	chains, err := client.GetCertificateChain(ctx, account, order.Certificate)
	if err != nil {
		return nil, fmt.Errorf("download certificate chain: %w", err)
	}
	if len(chains) == 0 {
		return nil, fmt.Errorf("ACME returned no certificate chains")
	}
	chainDER, err := parsePEMChain(chains[0].ChainPEM)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return nil, fmt.Errorf("marshal certificate key: %w", err)
	}
	slog.Info("acme: certificate issued", "domains", req.Domains, "replaced", req.Replaces != nil)
	return &Result{PrivKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), CertChainDER: chainDER}, nil
}

type dnsSolver struct {
	store    dnssrv.TXTHandler
	resolver *net.Resolver
	mu       sync.Mutex
	cleanups map[string][]dnssrv.CleanupFunc
}

// Present publishes the DNS-01 TXT value and retains its exact cleanup callback.
func (s *dnsSolver) Present(ctx context.Context, challenge ariacme.Challenge) error {
	name := challenge.DNS01TXTRecordName() + "."
	cleanup, err := s.store.SetTXTWithCleanup(ctx, name, challenge.DNS01KeyAuthorization(), txtRecordTTL)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cleanups[name] = append(s.cleanups[name], cleanup)
	s.mu.Unlock()
	return nil
}

// Wait blocks until the published DNS-01 TXT value is visible.
func (s *dnsSolver) Wait(ctx context.Context, challenge ariacme.Challenge) error {
	return waitForPropagation(ctx, s.resolver, challenge.DNS01TXTRecordName()+".", challenge.DNS01KeyAuthorization())
}

// cleanupAll removes every TXT value left behind by an interrupted flow.
func (s *dnsSolver) cleanupAll(ctx context.Context) {
	s.mu.Lock()
	cleanups := s.cleanups
	s.cleanups = make(map[string][]dnssrv.CleanupFunc)
	s.mu.Unlock()
	for name, callbacks := range cleanups {
		for _, cleanup := range callbacks {
			if err := cleanup(ctx); err != nil {
				slog.Warn("acme: DNS cleanup failed", "name", name, "error", err)
			}
		}
	}
}

// parsePEMChain validates and returns every certificate in a PEM chain.
func parsePEMChain(data []byte) ([][]byte, error) {
	var chain [][]byte
	for rest := data; len(rest) > 0; {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		if block.Type == "CERTIFICATE" {
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return nil, fmt.Errorf("parse ACME certificate chain: %w", err)
			}
			chain = append(chain, block.Bytes)
		}
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("ACME certificate chain is empty")
	}
	return chain, nil
}

// waitForPropagation polls DNS until the expected TXT value appears under fqdn.
func waitForPropagation(ctx context.Context, resolver *net.Resolver, fqdn, expected string) error {
	slog.Info("waiting for DNS propagation", "fqdn", fqdn)

	name := strings.TrimSuffix(fqdn, ".")

	if resolver == nil {
		resolver = net.DefaultResolver
	}

	ticker := time.NewTicker(propagationDelay)
	defer ticker.Stop()

	timeout := time.NewTimer(propagationTimeout)
	defer timeout.Stop()

	for {
		records, err := resolver.LookupTXT(ctx, name)
		if err == nil {
			for _, r := range records {
				if r == expected {
					slog.Info("DNS propagation confirmed", "fqdn", fqdn)
					return nil
				}
			}
		}

		slog.Debug("TXT record not yet visible, retrying", "fqdn", fqdn)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.C:
			return fmt.Errorf("timeout waiting for TXT record on %s: %w", fqdn, ErrPropagationTimeout)
		case <-ticker.C:
		}
	}
}

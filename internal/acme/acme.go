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
//	   WaitOrder                                ← order → "ready"
//	   CreateOrderCert                          ← finalize, get chain
//	   defer: cleanup TXT records
package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	acmez "github.com/mholt/acmez/v3"
	ariacme "github.com/mholt/acmez/v3/acme"
	"golang.org/x/crypto/acme"

	"lucor.dev/lancert/internal/dnssrv"
)

// ErrPropagationTimeout indicates that the DNS TXT record did not become
// visible within the propagation timeout window.
var ErrPropagationTimeout = errors.New("DNS propagation timeout")

// ErrRateLimited identifies an ACME rate-limit response.
var ErrRateLimited = errors.New("ACME rate limit exceeded")

// ErrAlreadyReplaced identifies a predecessor that the CA already replaced.
var ErrAlreadyReplaced = errors.New("ACME certificate already replaced")

// RateLimitError preserves the upstream Retry-After duration.
type RateLimitError struct {
	Err        error
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string                     { return e.Err.Error() }
func (e *RateLimitError) Unwrap() error                     { return e.Err }
func (e *RateLimitError) RetryAfterDuration() time.Duration { return e.RetryAfter }

type retryCaptureTransport struct {
	base  http.RoundTripper
	mu    sync.Mutex
	retry time.Duration
}

func (t *retryCaptureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if resp != nil {
		if value := resp.Header.Get("Retry-After"); value != "" {
			var d time.Duration
			if seconds, parseErr := strconv.Atoi(value); parseErr == nil {
				d = time.Duration(seconds) * time.Second
			} else if when, parseErr := http.ParseTime(value); parseErr == nil {
				d = time.Until(when)
			}
			if d > 0 {
				t.mu.Lock()
				t.retry = d
				t.mu.Unlock()
			}
		}
	}
	return resp, err
}

func (t *retryCaptureTransport) retryAfter() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.retry
}

const (
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
	LocalDirectoryURL                 = "https://127.0.0.1:14000/dir"
)

const defaultLocalCACert = ".mise/pebble/rootCA.pem"

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
		return LocalDirectoryURL, nil
	default:
		return "", fmt.Errorf("invalid ACME environment %q", env)
	}
}

func localHTTPClient(caPath string) (*http.Client, error) {
	if caPath == "" {
		caPath = defaultLocalCACert
	}
	data, err := os.ReadFile(filepath.Clean(caPath))
	if err != nil {
		return nil, fmt.Errorf("read Pebble CA certificate %q: %w", caPath, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("parse Pebble CA certificate %q", caPath)
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}, nil
}

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
		return &http.Client{Transport: base}, nil, nil
	}
	transport := &retryCaptureTransport{base: base}
	return &http.Client{Transport: transport}, transport, nil
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

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}

// Issue performs the ACME DNS-01 flow using the low-level ARI-capable client.
func Issue(ctx context.Context, req Request) (*Result, error) {
	return issueLowLevel(ctx, req)
}

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
	order, err = client.NewOrder(ctx, account, order)
	if err != nil {
		var problem ariacme.Problem
		if errors.As(err, &problem) {
			if problem.Type == ariacme.ProblemTypeRateLimited {
				return nil, &RateLimitError{Err: fmt.Errorf("%w: %v", ErrRateLimited, err), RetryAfter: transport.retryAfter()}
			}
			if problem.Type == ariacme.ProblemTypeAlreadyReplaced {
				return nil, fmt.Errorf("%w: %v", ErrAlreadyReplaced, err)
			}
		}
		return nil, fmt.Errorf("create ACME order: %w", err)
	}
	solver := &dnsSolver{store: req.TXTStore, resolver: req.Resolver, cleanups: make(map[string]dnssrv.CleanupFunc)}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		for name, cleanup := range solver.cleanups {
			if cleanup != nil {
				if err := cleanup(cleanupCtx); err != nil {
					slog.Warn("acme: DNS cleanup failed", "name", name, "error", err)
				}
			}
		}
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

func issueHighLevel(ctx context.Context, req Request) (*Result, error) {
	directoryURL := letsEncryptProduction
	solver := &dnsSolver{store: req.TXTStore, resolver: req.Resolver, cleanups: make(map[string]dnssrv.CleanupFunc)}
	transport := &retryCaptureTransport{base: http.DefaultTransport}
	client := &acmez.Client{
		Client:           &ariacme.Client{Directory: directoryURL, HTTPClient: &http.Client{Transport: transport}},
		ChallengeSolvers: map[string]acmez.Solver{ariacme.ChallengeTypeDNS01: solver},
	}
	account := ariacme.Account{PrivateKey: req.AccountKey}
	if req.Email != "" {
		account.Contact = []string{"mailto:" + req.Email}
	}
	registered, err := client.NewAccount(ctx, account)
	if err != nil {
		registered, err = client.GetAccount(ctx, account)
		if err != nil {
			return nil, fmt.Errorf("register or load ACME account: %w", err)
		}
	} else {
		slog.Info("acme: registered account")
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate certificate key: %w", err)
	}
	csr, err := acmez.NewCSR(certKey, req.Domains)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	params, err := acmez.OrderParametersFromCSR(registered, csr)
	if err != nil {
		return nil, fmt.Errorf("create ACME order parameters: %w", err)
	}
	params.Replaces = req.Replaces
	chains, err := client.ObtainCertificate(ctx, params)
	if err != nil {
		var problem ariacme.Problem
		if errors.As(err, &problem) {
			if problem.Type == ariacme.ProblemTypeRateLimited {
				wrapped := &RateLimitError{Err: fmt.Errorf("%w: %v", ErrRateLimited, err), RetryAfter: transport.retryAfter()}
				return nil, wrapped
			}
			if problem.Type == ariacme.ProblemTypeAlreadyReplaced {
				return nil, fmt.Errorf("%w: %v", ErrAlreadyReplaced, err)
			}
		}
		return nil, fmt.Errorf("obtain certificate: %w", err)
	}
	if len(chains) == 0 || len(chains[0].ChainPEM) == 0 {
		return nil, fmt.Errorf("ACME returned no certificate chain")
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
	cleanups map[string]dnssrv.CleanupFunc
}

func (s *dnsSolver) Present(ctx context.Context, challenge ariacme.Challenge) error {
	name := challenge.DNS01TXTRecordName() + "."
	cleanup, err := s.store.SetTXTWithCleanup(ctx, name, challenge.DNS01KeyAuthorization(), txtRecordTTL)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cleanups[name] = cleanup
	s.mu.Unlock()
	return nil
}

func (s *dnsSolver) Wait(ctx context.Context, challenge ariacme.Challenge) error {
	return waitForPropagation(ctx, s.resolver, challenge.DNS01TXTRecordName()+".", challenge.DNS01KeyAuthorization())
}

func (s *dnsSolver) CleanUp(ctx context.Context, challenge ariacme.Challenge) error {
	name := challenge.DNS01TXTRecordName() + "."
	s.mu.Lock()
	cleanup := s.cleanups[name]
	delete(s.cleanups, name)
	s.mu.Unlock()
	if cleanup == nil {
		return nil
	}
	return cleanup(ctx)
}

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

// issueLegacy is retained temporarily for comparison while the ARI client is
// exercised; it is not used by the service.
func issueLegacy(ctx context.Context, req Request) (*Result, error) {
	directoryURL := letsEncryptProduction

	client := &acme.Client{
		Key:          req.AccountKey,
		DirectoryURL: directoryURL,
	}

	acct := &acme.Account{}
	if req.Email != "" {
		acct.Contact = []string{"mailto:" + req.Email}
	}

	// Register always — the ACME spec requires this call for account lookup by
	// key. ErrAccountAlreadyExists is the expected happy-path response for
	// returning clients; it is not an error.
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil {
		if err != acme.ErrAccountAlreadyExists {
			return nil, fmt.Errorf("register account: %w", err)
		}
		slog.Info("using existing ACME account")
	} else {
		slog.Info("registered new ACME account")
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(req.Domains...))
	if err != nil {
		return nil, fmt.Errorf("authorize order: %w", err)
	}

	slog.Info("order created", "domains", req.Domains, "status", order.Status)

	var cleanups []dnssrv.CleanupFunc

	defer func() {
		// Use a fresh context: the parent ctx is likely cancelled by the time
		// this defer runs (error path, timeout, or shutdown signal). Reusing it
		// would silently skip cleanup, leaving stale TXT records in the DNS
		// store that would interfere with future challenge flows.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()

		for _, cleanup := range cleanups {
			if err := cleanup(cleanupCtx); err != nil {
				slog.Warn("cleanup failed", "error", err)
			}
		}
	}()

	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, fmt.Errorf("get authorization: %w", err)
		}

		if authz.Status == acme.StatusValid {
			slog.Info("authorization already valid", "domain", authz.Identifier.Value)
			continue
		}

		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}

		if chal == nil {
			return nil, fmt.Errorf("no dns-01 challenge found for %s", authz.Identifier.Value)
		}

		txtValue, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return nil, fmt.Errorf("compute dns-01 record: %w", err)
		}

		fqdn := "_acme-challenge." + authz.Identifier.Value + "."

		slog.Info("presenting dns-01 challenge", "fqdn", fqdn)

		cleanup, err := req.TXTStore.SetTXTWithCleanup(ctx, fqdn, txtValue, txtRecordTTL)
		if err != nil {
			return nil, fmt.Errorf("present challenge for %s: %w", authz.Identifier.Value, err)
		}
		cleanups = append(cleanups, cleanup)

		// Confirm propagation before calling Accept. LE validates the TXT record
		// immediately on Accept — if it is not visible yet, the challenge fails
		// permanently and the order cannot be retried.
		if err := waitForPropagation(ctx, req.Resolver, fqdn, txtValue); err != nil {
			return nil, fmt.Errorf("dns propagation for %s: %w", authz.Identifier.Value, err)
		}

		if _, err := client.Accept(ctx, chal); err != nil {
			return nil, fmt.Errorf("accept challenge for %s: %w", authz.Identifier.Value, err)
		}

		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			return nil, fmt.Errorf("wait authorization for %s: %w", authz.Identifier.Value, err)
		}

		slog.Info("authorization valid", "domain", authz.Identifier.Value)
	}

	// P256 is broadly supported by LE and all major TLS clients. P384 would
	// also be accepted but adds no practical security benefit for 90-day certs.
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate certificate key: %w", err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: req.Domains[0]},
		DNSNames: req.Domains,
	}, certKey)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	// The order transitions to "ready" only after all authorizations are valid.
	// Finalizing before that state returns an error from LE.
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, fmt.Errorf("wait order: %w", err)
	}

	certChainDER, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, fmt.Errorf("create order cert: %w", err)
	}

	slog.Info("certificate issued", "domains", req.Domains)

	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return nil, fmt.Errorf("marshal certificate key: %w", err)
	}

	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	return &Result{
		PrivKeyPEM:   privKeyPEM,
		CertChainDER: certChainDER,
	}, nil
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

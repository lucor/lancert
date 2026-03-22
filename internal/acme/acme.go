// Package acme performs ACME DNS-01 certificate issuance against Let's Encrypt.
//
// DNS-01 is the only challenge type used here because lancert issues certificates
// for RFC 1918 private IPs. Those addresses are unreachable from the public
// internet, making HTTP-01 and TLS-ALPN-01 impossible — LE's validators cannot
// reach them. DNS-01 works because lancert is itself the authoritative nameserver
// for the zone, so it can provision TXT records without any external dependency.
//
// Issuance flow:
//
//	Register / lookup account by key
//	└─ AuthorizeOrder (one order, N domains)
//	   └─ for each domain authorization:
//	      ├─ SetTXT(_acme-challenge.<domain>)   ← in-memory DNS store
//	      ├─ waitForPropagation                 ← poll until TXT visible
//	      ├─ Accept challenge                   ← notify LE to validate
//	      └─ WaitAuthorization                  ← poll until authz valid
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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"lucor.dev/lancert/internal/dnssrv"
)

// ErrPropagationTimeout indicates that the DNS TXT record did not become
// visible within the propagation timeout window.
var ErrPropagationTimeout = errors.New("DNS propagation timeout")

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

// Request holds the parameters for certificate issuance.
type Request struct {
	Domains    []string
	Email      string
	AccountKey *ecdsa.PrivateKey
	Staging    bool
	TXTStore   dnssrv.TXTHandler
	// Resolver is the DNS resolver used to confirm TXT propagation.
	// nil uses the system default, which queries our authoritative DNS.
	// Tests can inject a resolver pointing at the in-process DNS server
	// to verify that TXT records are actually being served.
	Resolver *net.Resolver
}

// Result holds the issued certificate data.
type Result struct {
	PrivKeyPEM   []byte
	CertChainDER [][]byte
}

// Issue performs the full ACME DNS-01 flow and returns the certificate chain.
func Issue(ctx context.Context, req Request) (*Result, error) {
	directoryURL := letsEncryptProduction
	if req.Staging {
		directoryURL = letsEncryptStaging
	}

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

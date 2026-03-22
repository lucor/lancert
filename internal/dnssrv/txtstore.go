// TXTStore and related types are defined in this file (package dnssrv).
//
// # Why multiple values per FQDN
//
// A certificate request for both the bare subdomain and the wildcard
// (e.g. "192-168-1-50.lancert.dev" and "*.192-168-1-50.lancert.dev") results
// in two separate ACME authorizations that both require a TXT record under the
// same _acme-challenge FQDN. Both values must be present simultaneously because
// LE validates each authorization independently. The store accumulates values
// per FQDN rather than replacing them to support this case.
//
// # Why cleanup is a returned closure
//
// The acme package owns the challenge lifecycle. Returning a CleanupFunc lets
// the caller remove exactly the value it added — by value identity, not by
// FQDN — without affecting other concurrent challenges on the same FQDN.
// The closure also decouples cleanup from the issuance context: acme.Issue
// calls it in a separate context with its own timeout so that TXT records are
// always removed even when the parent context is cancelled.
//
// # Why the ttl parameter is ignored
//
// The TTL is enforced at the DNS response layer (hardcoded to 0 in handleTXT)
// so that resolvers never cache challenge records. Storing the TTL in the
// map and expiring entries would add complexity with no benefit — cleanup is
// always triggered explicitly by the ACME flow.
package dnssrv

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// CleanupFunc removes a DNS TXT record created during an ACME challenge.
type CleanupFunc func(ctx context.Context) error

// TXTHandler creates and removes DNS TXT records for ACME DNS-01 challenges.
type TXTHandler interface {
	SetTXTWithCleanup(ctx context.Context, fqdn, value string, ttl time.Duration) (CleanupFunc, error)
}

// TXTStore is an in-memory store for ACME DNS-01 challenge TXT records.
// It accumulates multiple values per FQDN (needed for wildcard + bare
// certs that share the same _acme-challenge name).
// Safe for concurrent use.
type TXTStore struct {
	mu      sync.RWMutex
	records map[string][]string // fqdn -> []value
}

// NewTXTStore creates an empty TXT challenge store.
func NewTXTStore() *TXTStore {
	return &TXTStore{
		records: make(map[string][]string),
	}
}

// SetTXTWithCleanup adds a TXT value for the given FQDN and returns a
// cleanup function that removes that specific value. Implements TXTHandler.
func (s *TXTStore) SetTXTWithCleanup(_ context.Context, fqdn, value string, _ time.Duration) (CleanupFunc, error) {
	s.mu.Lock()
	s.records[fqdn] = append(s.records[fqdn], value)
	s.mu.Unlock()

	slog.Info("txtstore: added record", "fqdn", fqdn)

	cleanup := func(_ context.Context) error {
		s.mu.Lock()
		defer s.mu.Unlock()

		values := s.records[fqdn]
		for i, v := range values {
			if v == value {
				s.records[fqdn] = append(values[:i], values[i+1:]...)
				break
			}
		}

		if len(s.records[fqdn]) == 0 {
			delete(s.records, fqdn)
		}

		slog.Info("txtstore: removed record", "fqdn", fqdn)
		return nil
	}

	return cleanup, nil
}

// Lookup returns the TXT values stored for the given FQDN, or nil if
// none exist. The FQDN must include the trailing dot.
func (s *TXTStore) Lookup(fqdn string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	vals := s.records[fqdn]
	if len(vals) == 0 {
		return nil
	}

	out := make([]string, len(vals))
	copy(out, vals)
	return out
}

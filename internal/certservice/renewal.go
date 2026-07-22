package certservice

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	acmeissue "lucor.dev/lancert/internal/acme"
	"lucor.dev/lancert/internal/certstore"
	"lucor.dev/lancert/internal/privateip"
)

const (
	renewalPollInterval = time.Minute
	ariErrorRetry       = 6 * time.Hour
	renewalFailureRetry = time.Hour
)

// StartRenewalWorker starts the single sequential ARI lifecycle worker.
func (s *Service) StartRenewalWorker(ctx context.Context) {
	go s.renewalLoop(ctx)
}

func (s *Service) renewalLoop(ctx context.Context) {
	slog.Info("certservice: ARI renewal worker started")
	defer slog.Info("certservice: ARI renewal worker stopped")
	s.reconcileRenewals(ctx)
	ticker := time.NewTicker(renewalPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.reconcileRenewals(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func (s *Service) reconcileRenewals(ctx context.Context) {
	entries, err := s.store.Inventory()
	if err != nil {
		slog.Error("certservice: renewal inventory failed", "error", err)
		return
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		if !entry.Ready || !entry.Addr.IsValid() {
			continue
		}
		if err := s.reconcileCertificate(ctx, entry.Addr); err != nil {
			slog.Error("certservice: renewal reconciliation failed", "addr", entry.Addr, "error", err)
		}
	}
}

func (s *Service) reconcileCertificate(ctx context.Context, addr netip.Addr) error {
	bundle, err := s.store.Load(addr)
	if err != nil || bundle == nil {
		return err
	}
	if time.Now().After(bundle.Meta.NotAfter) {
		return nil
	}
	if !bundle.Renewal.NextAttempt.IsZero() && time.Now().Before(bundle.Renewal.NextAttempt) {
		return nil
	}
	leaf, err := leafFromBundle(bundle)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	state := bundle.Renewal
	if state.NextCheck.IsZero() || !now.Before(state.NextCheck) {
		info, infoErr := acmeissue.GetRenewalInfo(ctx, leaf, s.config.Environment, s.config.CACertPath)
		if infoErr != nil || !validWindow(info.WindowStart, info.WindowEnd) {
			state.WindowStart = time.Time{}
			state.WindowEnd = time.Time{}
			state.RenewAt = bundle.Meta.NotAfter.Add(-RenewalWindow)
			state.NextCheck = now.Add(ariErrorRetry)
			slog.Warn("certservice: using renewal fallback", "addr", addr, "error", infoErr)
		} else {
			state.WindowStart = info.WindowStart
			state.WindowEnd = info.WindowEnd
			state.RenewAt = chooseRenewAt(state.CertificateID, info.WindowStart, info.WindowEnd)
			state.NextCheck = info.RetryAfter
			if state.NextCheck.IsZero() || state.NextCheck.Before(now.Add(time.Minute)) {
				state.NextCheck = now.Add(time.Hour)
			}
			slog.Info("certservice: ARI window scheduled", "addr", addr, "renew_at", state.RenewAt, "next_check", state.NextCheck)
		}
		if err := s.store.SaveBundle(addr, &certstore.CertBundle{PrivKeyPEM: bundle.PrivKeyPEM, FullChainPEM: bundle.FullChainPEM, Meta: bundle.Meta, Renewal: state}); err != nil {
			return err
		}
		bundle.Renewal = state
	}
	if now.Before(bundle.Renewal.RenewAt) {
		return nil
	}
	return s.renewCertificate(ctx, addr, bundle, leaf)
}

func (s *Service) renewCertificate(ctx context.Context, addr netip.Addr, current *certstore.CertBundle, leaf *x509.Certificate) error {
	key := addr.String()
	slog.Info("certservice: renewal started", "addr", addr, "certificate_id", current.Renewal.CertificateID)
	_, err, _ := s.sfGroup.Do(key, func() (any, error) {
		ctx, cancel := context.WithTimeout(ctx, issuanceTimeout)
		defer cancel()
		domains := privateip.Domains(addr, s.config.Zone)
		result, err := acmeissue.Issue(ctx, acmeissue.Request{Domains: domains[:], Email: s.config.Email, AccountKey: s.config.AccountKey, Environment: s.config.Environment, CACertPath: s.config.CACertPath, Resolver: s.config.Resolver, TXTStore: s.txtStore, Replaces: leaf})
		if err != nil {
			current.Renewal.NextAttempt = time.Now().UTC().Add(retryAfter(err))
			_ = s.store.SaveBundle(addr, current)
			slog.Warn("certservice: renewal failed", "addr", addr, "next_attempt", current.Renewal.NextAttempt, "error", err)
			return nil, err
		}
		if err := s.store.Save(addr, result.PrivKeyPEM, result.CertChainDER); err != nil {
			return nil, err
		}
		fresh, err := s.store.Load(addr)
		if err != nil || fresh == nil {
			return nil, fmt.Errorf("reload renewed bundle: %w", err)
		}
		fresh.Renewal.NextCheck = time.Time{}
		fresh.Renewal.NextAttempt = time.Time{}
		if err := s.store.SaveBundle(addr, fresh); err != nil {
			return nil, err
		}
		slog.Info("certservice: renewal succeeded", "addr", addr)
		return fresh, nil
	})
	return err
}

func retryAfter(err error) time.Duration {
	var problem interface{ RetryAfterDuration() time.Duration }
	if errors.As(err, &problem) {
		if d := problem.RetryAfterDuration(); d > 0 {
			return d
		}
	}
	return renewalFailureRetry
}

func leafFromBundle(bundle *certstore.CertBundle) (*x509.Certificate, error) {
	block, _ := pem.Decode(bundle.FullChainPEM)
	if block == nil {
		return nil, fmt.Errorf("certificate chain is empty")
	}
	return x509.ParseCertificate(block.Bytes)
}

func validWindow(start, end time.Time) bool {
	return !start.IsZero() && !end.IsZero() && start.Before(end)
}

func chooseRenewAt(id string, start, end time.Time) time.Time {
	if !start.Before(end) {
		return end
	}
	h := sha256.New()
	h.Write([]byte(id))
	h.Write([]byte{0})
	h.Write([]byte(start.UTC().Format(time.RFC3339Nano)))
	h.Write([]byte{0})
	h.Write([]byte(end.UTC().Format(time.RFC3339Nano)))
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	ns := binary.BigEndian.Uint64(sum[:8])
	return start.Add(time.Duration(ns % uint64(end.Sub(start))))
}

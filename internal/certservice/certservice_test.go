package certservice

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	ariacme "github.com/mholt/acmez/v3/acme"
	"github.com/stretchr/testify/require"
	acmeissue "lucor.dev/lancert/internal/acme"
	"lucor.dev/lancert/internal/certstore"
	"lucor.dev/lancert/internal/dnssrv"
	"lucor.dev/lancert/internal/metrics"
)

func TestClassifyIssueErrorUsesAcmezProblems(t *testing.T) {
	auth := ariacme.Problem{Type: "urn:ietf:params:acme:error:unauthorized", Status: http.StatusForbidden}
	require.Equal(t, http.StatusBadGateway, classifyIssueError(auth))
	require.Equal(t, http.StatusServiceUnavailable, classifyIssueError(acmeissue.ErrRateLimited))
}

func TestSuspendedServiceDoesNotStartCertificateWork(t *testing.T) {
	baseDir := t.TempDir()
	marker := filepath.Join(baseDir, "existing-material")
	require.NoError(t, os.WriteFile(marker, []byte("preserve"), 0o600))

	svc := New(
		Config{
			Zone:        "lancert.dev",
			Environment: acmeissue.EnvironmentStaging,
			Suspended:   true,
		},
		certstore.New(baseDir),
		dnssrv.NewTXTStore(),
		metrics.Disabled{},
	)
	addr := netip.MustParseAddr("192.168.1.50")
	var issueCalls, renewalInfoCalls int
	svc.issueCertificate = func(context.Context, acmeissue.Request) (*acmeissue.Result, error) {
		issueCalls++
		return nil, errors.New("unexpected issuance call")
	}
	svc.getRenewalInfo = func(context.Context, *x509.Certificate, acmeissue.Environment, string) (acmeissue.RenewalInfo, error) {
		renewalInfoCalls++
		return acmeissue.RenewalInfo{}, errors.New("unexpected ARI call")
	}

	admitCalled := false
	status := svc.TriggerIssuanceIf(addr, func() bool {
		admitCalled = true
		return true
	})
	require.True(t, status.Suspended)
	require.False(t, admitCalled)
	require.Empty(t, svc.issues)

	_, err := svc.GetOrIssue(context.Background(), addr)
	require.ErrorIs(t, err, ErrSuspended)

	svc.Pregen(context.Background())
	svc.reconcileRenewals(context.Background())
	require.ErrorIs(t, svc.reconcileCertificate(context.Background(), addr), ErrSuspended)
	require.ErrorIs(t, svc.renewCertificate(context.Background(), addr, nil, nil, false), ErrSuspended)
	svc.StartRenewalWorker(context.Background())
	require.Zero(t, issueCalls)
	require.Zero(t, renewalInfoCalls)

	data, err := os.ReadFile(marker)
	require.NoError(t, err)
	require.Equal(t, "preserve", string(data))
}

func TestTriggerIssuanceAdmissionOnlyAppliesToNewWork(t *testing.T) {
	pendingAddr := netip.MustParseAddr("192.168.1.10")
	deniedAddr := netip.MustParseAddr("192.168.1.11")
	svc := &Service{issues: map[string]*issueRecord{
		pendingAddr.String(): {pending: true},
	}}

	called := false
	status := svc.TriggerIssuanceIf(pendingAddr, func() bool {
		called = true
		return false
	})
	require.True(t, status.Pending)
	require.False(t, called)

	status = svc.TriggerIssuanceIf(deniedAddr, func() bool {
		called = true
		return false
	})
	require.True(t, called)
	require.True(t, status.RateLimited)
	_, exists := svc.issues[deniedAddr.String()]
	require.False(t, exists)
}

func TestTriggerIssuanceAdmissionSkipsFailureCooldown(t *testing.T) {
	addr := netip.MustParseAddr("192.168.1.12")
	svc := &Service{issues: map[string]*issueRecord{
		addr.String(): {fail: &failRecord{
			err: errors.New("authorization failed"), at: time.Now(), status: http.StatusBadGateway,
		}},
	}}

	called := false
	status := svc.TriggerIssuanceIf(addr, func() bool {
		called = true
		return true
	})

	require.False(t, called)
	require.NotNil(t, status.Fail)
	require.Equal(t, http.StatusBadGateway, status.Fail.Status)
}

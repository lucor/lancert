package certservice

import (
	"errors"
	"net/http"
	"net/netip"
	"testing"
	"time"

	ariacme "github.com/mholt/acmez/v3/acme"
	"github.com/stretchr/testify/require"
	acmeissue "lucor.dev/lancert/internal/acme"
)

func TestClassifyIssueErrorUsesAcmezProblems(t *testing.T) {
	auth := ariacme.Problem{Type: "urn:ietf:params:acme:error:unauthorized", Status: http.StatusForbidden}
	require.Equal(t, http.StatusBadGateway, classifyIssueError(auth))
	require.Equal(t, http.StatusServiceUnavailable, classifyIssueError(acmeissue.ErrRateLimited))
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

package certservice

import (
	"net/http"
	"testing"

	ariacme "github.com/mholt/acmez/v3/acme"
	"github.com/stretchr/testify/require"
	acmeissue "lucor.dev/lancert/internal/acme"
)

func TestClassifyIssueErrorUsesAcmezProblems(t *testing.T) {
	auth := ariacme.Problem{Type: "urn:ietf:params:acme:error:unauthorized", Status: http.StatusForbidden}
	require.Equal(t, http.StatusBadGateway, classifyIssueError(auth))
	require.Equal(t, http.StatusServiceUnavailable, classifyIssueError(acmeissue.ErrRateLimited))
}

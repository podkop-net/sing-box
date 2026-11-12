package v2rayxhttp

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/sagernet/sing-box/common/tls"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/stretchr/testify/require"
)

// Of an error hidden nothing is told but its text and whether a REALITY server failed the
// verification.
func TestHiddenRealityVerification(t *testing.T) {
	hidden := hideHTTPError(E.Cause(tls.ErrRealityVerification, "dial"))
	require.EqualError(t, hidden, "dial: reality verification failed")
	for _, err := range []error{hidden, hideHTTPError(hidden), E.Cause(hidden, "xhttp")} {
		require.ErrorIs(t, err, tls.ErrRealityVerification)
	}
	for _, cause := range []error{os.ErrDeadlineExceeded, context.Canceled, http.ErrServerClosed} {
		err := hideHTTPError(E.Cause(cause, "reality verification failed"))
		require.NotErrorIs(t, err, tls.ErrRealityVerification)
		require.NotErrorIs(t, err, cause)
	}
}

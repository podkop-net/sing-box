//go:build with_utls

package tls

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"testing"

	E "github.com/sagernet/sing/common/exceptions"

	"github.com/stretchr/testify/require"
)

// Every failed verification is ErrRealityVerification, through what wraps it on the way up, and
// keeps its text and its cause.
func TestErrRealityVerification(t *testing.T) {
	cause := x509.HostnameError{Certificate: &x509.Certificate{DNSNames: []string{"example.org"}}, Host: "example.com"}
	const note = ", possibly because of the uTLS fingerprint edge: REALITY servers since Xray-core v26.9.8 reject a Client Hello without an X25519MLKEM768 key share"
	for _, testCase := range []struct {
		name   string
		config RealityClientConfig
		cause  error
		text   string
	}{
		{"bare", RealityClientConfig{}, nil, "reality verification failed"},
		{"with a cause", RealityClientConfig{}, io.EOF, "reality verification failed: EOF"},
		{"a fingerprint without the key share", RealityClientConfig{classicFingerprint: "edge"}, nil,
			"reality verification failed" + note + ", use chrome, firefox, safari, random or randomized"},
		{"one the fallback has gone on to", RealityClientConfig{classicFingerprint: "edge", classicFallback: true}, cause,
			"reality verification failed" + note + ": " + cause.Error()},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.config.verificationFailed(testCase.cause)
			require.EqualError(t, err, testCase.text)
			wrapped := E.Cause(err, "create client transport")
			require.ErrorIs(t, wrapped, ErrRealityVerification)
			require.True(t, realityVerificationError(wrapped))
			if testCase.cause != nil {
				require.ErrorIs(t, wrapped, testCase.cause)
			}
			var stranger *realityStrangerError
			require.Equal(t, testCase.config.classicFingerprint != "", errors.As(wrapped, &stranger))
		})
	}
	// the certificate of the target, refused by this host's roots, is a failed verification for the
	// block detector, but no word of REALITY
	require.True(t, realityVerificationError(cause))
	require.NotErrorIs(t, cause, ErrRealityVerification)
	for _, err := range []error{context.DeadlineExceeded, io.EOF, E.New("reality verification failed")} {
		require.False(t, realityVerificationError(err), err)
	}
}

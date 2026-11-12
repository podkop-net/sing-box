package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// pipeDialer gives each dial one end of a pipe.
type pipeDialer struct{}

func (pipeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func (pipeDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("no packets")
}

// echRejectedConn ends every handshake with the server's rejection of ECH, with a list to retry.
type echRejectedConn struct {
	Conn
}

func (echRejectedConn) HandshakeContext(ctx context.Context) error {
	return &tls.ECHRejectionError{RetryConfigList: []byte{1}}
}

func (echRejectedConn) Close() error {
	return nil
}

// echRejectedConfig is a client configuration whose handshakes the server's ECH rejects; it tells
// which configuration the fingerprint fallback of a dial was asked of.
type echRejectedConfig struct {
	Config
	name     string
	asked    *[]string
	fallback fingerprintDial
}

func (c echRejectedConfig) HandshakeTimeout() time.Duration {
	return 0
}

func (c echRejectedConfig) Client(conn net.Conn) (Conn, error) {
	return echRejectedConn{}, nil
}

func (c echRejectedConfig) fingerprintDial() fingerprintDial {
	*c.asked = append(*c.asked, c.name)
	return c.fallback
}

// iteratingFallback would dial again after any failure it is told of.
type iteratingFallback struct {
	config   Config
	attempts int
	failures int
}

func (f *iteratingFallback) ready(ctx context.Context, destination M.Socksaddr) error { return nil }
func (f *iteratingFallback) done()                                                    {}
func (f *iteratingFallback) answered()                                                {}

func (f *iteratingFallback) attempt(conn net.Conn) (Config, bool) {
	f.attempts++
	return f.config, false
}

func (f *iteratingFallback) unanswered(destination M.Socksaddr) (bool, error) {
	return false, nil
}

func (f *iteratingFallback) failed(ctx context.Context, destination M.Socksaddr, err error) bool {
	f.failures++
	return f.failures < 4
}

// An ECH rejection is no matter of the fingerprint: the dial returns it at once for
// DialTLSContext to retry with the server's ECH configuration, without trying the next
// fingerprint, and the candidates of the dial are made of the configuration it was given (the
// retry's clone carries the server's ECH list) (podkop-engine, tls-fp-fallback).
func TestECHRejectionLeavesTheFingerprintFallback(t *testing.T) {
	var asked []string
	fallback := &iteratingFallback{}
	original := echRejectedConfig{name: "original", asked: &asked, fallback: fallback}
	retry := echRejectedConfig{name: "retry", asked: &asked, fallback: fallback}
	fallback.config = retry
	dialer := NewDialer(pipeDialer{}, original).(*defaultDialer)
	_, err := dialer.dialContext(context.Background(), M.ParseSocksaddrHostPort("192.0.2.1", 443), retry)
	var echErr *tls.ECHRejectionError
	require.ErrorAs(t, err, &echErr)
	require.Equal(t, 1, fallback.attempts, "an ECH rejection tried the next fingerprint")
	require.Zero(t, fallback.failures, "the fallback was told of an ECH rejection")
	require.Equal(t, []string{"retry"}, asked, "the candidates were not made of the configuration of the dial")
}

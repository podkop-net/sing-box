//go:build with_utls

package tls

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tlsspoof"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type upstreamDialer struct {
	N.Dialer
}

func (d upstreamDialer) Upstream() any {
	return d.Dialer
}

// detourOutbounds is the outbound manager of a detour: two outbounds to lead to.
type detourOutbounds struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m detourOutbounds) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}

var errDetourDialed = E.New("the detour was dialed")

// detourTarget is an outbound a detour leads to; it counts the dials and fails them.
type detourTarget struct {
	adapter.Outbound
	dialed *atomic.Int32
}

func (o detourTarget) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.dialed.Add(1)
	return nil, errDetourDialed
}

// directTarget is what a detour takes for a direct outbound.
type directTarget struct {
	detourTarget
}

func (o directTarget) IsEmpty() bool {
	return false
}

func newDetours() (outbounds detourOutbounds, proxyDialed *atomic.Int32, directDialed *atomic.Int32) {
	proxyDialed, directDialed = new(atomic.Int32), new(atomic.Int32)
	outbounds = detourOutbounds{outbounds: map[string]adapter.Outbound{
		"proxy":  detourTarget{dialed: proxyDialed},
		"direct": directTarget{detourTarget{dialed: directDialed}},
	}}
	return
}

// A dialer that goes through a proxy outbound is told apart from one that dials the
// server itself, also under the wrapper that resolves the server's name. A detour to a
// direct outbound dials the server itself; one that leads nowhere is left to the dial.
func TestThroughTunnel(t *testing.T) {
	outbounds, _, _ := newDetours()
	proxy := dialer.NewDetour(outbounds, "proxy", false)
	require.True(t, throughTunnel(proxy))
	require.True(t, throughTunnel(upstreamDialer{proxy}))
	direct := dialer.NewDetour(outbounds, "direct", false)
	require.False(t, throughTunnel(direct))
	require.False(t, throughTunnel(upstreamDialer{direct}))
	missing := dialer.NewDetour(outbounds, "missing", false)
	require.False(t, throughTunnel(missing))
	_, err := missing.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddrHostPort("192.0.2.1", 443))
	require.ErrorContains(t, err, "outbound detour not found: missing")
	require.False(t, throughTunnel(N.SystemDialer))
	require.False(t, throughTunnel(upstreamDialer{N.SystemDialer}))
}

// Inside the connection of a proxy outbound the socket is the tunnel's: tls.spoof would
// forge its ClientHello into that connection, and is refused before anything is dialed,
// also for a configuration wrapped for kernel TLS or for ECH taken from DNS. Through a
// detour to a direct outbound the socket is the server's, and the dial goes on.
func TestSpoofThroughDetour(t *testing.T) {
	if !tlsspoof.PlatformSupported {
		t.Skip("tls spoof is not supported here")
	}
	setFallback(t, true)
	logger, _ := newWarnLogger(t)
	options := realityOptionsForTest("chrome", false)
	options.Spoof = "packagist.org"
	config, err := NewClient(context.Background(), logger, "192.0.2.1", options)
	require.NoError(t, err)
	destination := M.ParseSocksaddrHostPort("192.0.2.1", 443)
	wrapped := map[string]Config{
		"as it is":   config,
		"kernel TLS": &KTLSClientConfig{Config: config},
		"ECH":        &ECHClientConfig{ECHCapableConfig: config.(ECHCapableConfig)},
	}
	for name, config := range wrapped {
		outbounds, proxyDialed, directDialed := newDetours()
		_, err = NewDialer(dialer.NewDetour(outbounds, "proxy", false), config).DialTLSContext(context.Background(), destination)
		require.ErrorContains(t, err, "tls.spoof does not work through a detour to a proxy outbound", name)
		require.Zero(t, proxyDialed.Load(), name)
		_, err = NewDialer(dialer.NewDetour(outbounds, "direct", false), config).DialTLSContext(context.Background(), destination)
		require.ErrorIs(t, err, errDetourDialed, name)
		require.EqualValues(t, 1, directDialed.Load(), name)
	}

	// a detour that leads nowhere says so itself, whatever the configuration asks for
	outbounds, proxyDialed, _ := newDetours()
	_, err = NewDialer(dialer.NewDetour(outbounds, "missing", false), config).DialTLSContext(context.Background(), destination)
	require.ErrorContains(t, err, "outbound detour not found: missing")
	require.Zero(t, proxyDialed.Load())

	// without tls.spoof nothing is refused
	plain, err := NewClient(context.Background(), logger, "192.0.2.1", realityOptionsForTest("chrome", false))
	require.NoError(t, err)
	_, err = NewDialer(dialer.NewDetour(outbounds, "proxy", false), plain).DialTLSContext(context.Background(), destination)
	require.ErrorIs(t, err, errDetourDialed)
	require.EqualValues(t, 1, proxyDialed.Load())
}

// askedConfig is a client configuration that counts how many dials asked it for the
// fingerprint fallback.
type askedConfig struct {
	Config
	asked *atomic.Int32
}

func (c askedConfig) fingerprintDial() fingerprintDial {
	c.asked.Add(1)
	return nil
}

// The fingerprint fallback is not used inside the connection of a proxy outbound: the
// first flight on that socket is not the ClientHello of this client. Through a detour to
// a direct outbound, and without a detour, it is.
func TestFallbackThroughDetour(t *testing.T) {
	outbounds, _, _ := newDetours()
	destination := M.ParseSocksaddrHostPort("192.0.2.1", 443)
	config := askedConfig{asked: new(atomic.Int32)}
	_, err := NewDialer(dialer.NewDetour(outbounds, "proxy", false), config).DialTLSContext(context.Background(), destination)
	require.ErrorIs(t, err, errDetourDialed)
	require.Zero(t, config.asked.Load())
	_, err = NewDialer(upstreamDialer{dialer.NewDetour(outbounds, "proxy", false)}, config).DialTLSContext(context.Background(), destination)
	require.ErrorIs(t, err, errDetourDialed)
	require.Zero(t, config.asked.Load())
	_, err = NewDialer(dialer.NewDetour(outbounds, "direct", false), config).DialTLSContext(context.Background(), destination)
	require.ErrorIs(t, err, errDetourDialed)
	require.EqualValues(t, 1, config.asked.Load())
	_, err = NewDialer(detourTarget{dialed: new(atomic.Int32)}, config).DialTLSContext(context.Background(), destination)
	require.ErrorIs(t, err, errDetourDialed)
	require.EqualValues(t, 2, config.asked.Load())
}

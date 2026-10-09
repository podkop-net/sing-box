package tls

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing/common"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The uTLS fingerprint fallback (podkop-engine).
//
// A middlebox that judges a TLS connection by its ClientHello may drop the ClientHello of
// one browser and pass that of another: the connection is made, the ClientHello is sent,
// and no acknowledgment ever comes for it. The handshake then waits out its whole
// timeout, on every connection. With the fallback on, the dialer watches the connection
// while the handshake runs; when the ClientHello stays unacknowledged it gives the
// connection up at once and dials again: with the same fingerprint once more, then with
// the next one of the list. The fingerprint that got through is the one used from then
// on, for the local address it worked from (another address is another network, where
// the configured one may work). When no fingerprint gets through, what drops the
// ClientHello does not choose by fingerprint: the fallback then rests, and connections
// are made exactly as without it, with the fingerprint that worked last. It rests as
// well when the fingerprint that was not answered is answered on the next connection, a
// loss on the way; when that keeps happening the fingerprint is left after all, since
// what drops only a part of its ClientHellos looks the same.
//
// The list is the option experimental.utls_fallback of the configuration or else the
// environment variable SING_BOX_UTLS_FALLBACK, comma-separated names of the
// utls.fingerprint option; the configured fingerprint is tried first. Without either
// nothing changes. It concerns the TLS clients with a uTLS fingerprint, REALITY included,
// dialed over a TCP socket of the kernel on Linux: not through a detour to a proxy
// outbound, and not a client with ECH taken from DNS or with kernel TLS, whose
// configuration is wrapped in another.

// fingerprintFallbackConfig is a client configuration that can go on with another
// fingerprint.
type fingerprintFallbackConfig interface {
	// fingerprintDial returns the fallback of one dial, nil when the configuration has
	// none.
	fingerprintDial() fingerprintDial
}

// fingerprintDial follows the attempts of one dial.
type fingerprintDial interface {
	// attempt returns the configuration for the handshake over conn, and whether the
	// ClientHello is to be watched.
	attempt(conn net.Conn) (config Config, watched bool)
	// answered tells that the handshake of the last attempt succeeded.
	answered()
	// unanswered tells that the ClientHello of the last attempt got no acknowledgment.
	// It reports whether to dial again, and the error of the dial when not.
	unanswered(destination M.Socksaddr) (again bool, err error)
	// failed tells that the handshake of the last attempt failed with err though its
	// ClientHello was not left unanswered. It reports whether to dial again.
	failed(ctx context.Context, destination M.Socksaddr, err error) (again bool)
}

// throughTunnel tells whether a dialer makes its connections inside those of another
// outbound. Such a connection is not a socket to the server: its first flight is the
// tunnel's, and some protocols send theirs only with the first payload, the ClientHello.
// A detour to a direct outbound (another uplink, by its interface or mark) is a socket
// to the server as any other. It is asked at the dial, not before: a dialer finds the
// outbound of its detour at the first use, and keeps what it found.
func throughTunnel(outboundDialer N.Dialer) bool {
	detour, isDetour := common.Cast[*dialer.DetourDialer](outboundDialer)
	if !isDetour {
		return false
	}
	target, err := detour.Dialer()
	if err != nil {
		// nothing is dialed through it: the dial returns this error
		return false
	}
	_, isDirect := target.(dialer.DirectDialer)
	return !isDirect
}

// helloWatch watches a connection for a ClientHello that the server does not acknowledge.
type helloWatch struct {
	stopped    chan struct{}
	finished   chan struct{}
	unanswered atomic.Bool
}

// stop ends the watch and reports whether it has closed the connection, the ClientHello
// having got no acknowledgment.
func (w *helloWatch) stop() bool {
	if w == nil {
		return false
	}
	close(w.stopped)
	<-w.finished
	return w.unanswered.Load()
}

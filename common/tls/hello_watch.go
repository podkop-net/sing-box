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
// Since 2026 the Russian DPI freezes the connections of some browser ClientHellos to a
// server when many are made to it at once: chrome (Chrome 133, with the X25519MLKEM768 key
// share), safari and randomized among them; the same ClientHello without the key share,
// and firefox, pass (measured in October 2026). A frozen ClientHello is never
// acknowledged; the handshake waits out its whole timeout, and so does every connection
// after it for a while. With the fallback on, a client tries its ClientHellos in this order
// and keeps the first that a server takes and the path lets through:
//
//  1. the configured fingerprint without its X25519MLKEM768 key share, as stock sing-box
//     sends it under REALITY;
//  2. firefox, with the key share: REALITY servers since Xray-core v26.9.8 refuse a
//     ClientHello without it (they answer it as a stranger's);
//  3. the configured fingerprint as it is.
//
// The dialer watches the connection while the handshake runs; when the ClientHello stays
// unacknowledged it gives the connection up at once and dials again: with the same
// ClientHello once more, then with the next one. A server that answers the ClientHello as a
// stranger's moves the client on at once. While nothing is known of a server, one dial
// tries the ClientHellos and the others wait for it: a burst of connections would
// otherwise freeze the path or pile up refusals on the server. The choice is kept for the
// local address it was made from (another address is another network) and in the cache
// file, for a day; then one dial tries the first ClientHello again. When none gets through,
// what drops the ClientHello does not choose by it: the fallback then rests, and
// connections are made with the ClientHello that worked last, the configured fingerprint
// when none has. It rests as well when the ClientHello that was not answered is answered on
// the next connection, a loss on the way; when that keeps happening it is left after all,
// since what drops only a part of the ClientHellos of one kind looks the same.
//
// The fallback is turned on by the option experimental.utls_fallback of the configuration,
// or else by the environment variable SING_BOX_UTLS_FALLBACK; the list of fingerprints the
// option may carry is no longer used. It concerns the TLS clients with a uTLS fingerprint,
// REALITY included, dialed over a TCP socket of the kernel on Linux: not through a detour
// to a proxy outbound, and not a client with ECH taken from DNS or with kernel TLS, whose
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
	// ready waits, before the connection is made, while another dial tries the
	// ClientHellos of a server nothing is known of.
	ready(ctx context.Context, destination M.Socksaddr) error
	// done ends the dial: what it held for the others is released.
	done()
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

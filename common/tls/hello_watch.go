package tls

import (
	"net"
	"sync/atomic"

	M "github.com/sagernet/sing/common/metadata"
)

// The uTLS fingerprint fallback (podkop-engine).
//
// A middlebox that judges a TLS connection by its ClientHello may drop the ClientHello of
// one browser and pass that of another: the connection is made, the ClientHello is sent,
// and no acknowledgment ever comes for it. The handshake then waits out its whole
// timeout, on every connection. With the fallback on, the dialer watches the connection
// while the handshake runs; when the ClientHello stays unacknowledged it gives the
// connection up at once and dials again with the next fingerprint of the list. The
// fingerprint that got through is the one used from then on, for the local address it
// worked from (another address is another network, where the configured one may work).
//
// The list is SING_BOX_UTLS_FALLBACK, comma-separated names of the utls.fingerprint
// option (the init script sets it from /etc/config/sing-box); the configured fingerprint
// is tried first. Without the variable nothing changes. It concerns the TLS clients with
// a uTLS fingerprint, REALITY included, dialed over a TCP socket of the kernel on Linux.

// fingerprintFallbackConfig is a client configuration that can go on with another
// fingerprint.
type fingerprintFallbackConfig interface {
	// fingerprintDial returns the fallback of one dial, nil when the configuration has
	// none.
	fingerprintDial() fingerprintDial
}

// fingerprintDial follows the attempts of one dial.
type fingerprintDial interface {
	// attempt returns the configuration for the handshake over conn.
	attempt(conn net.Conn) Config
	// answered tells that the handshake of the last attempt succeeded.
	answered()
	// unanswered tells that the ClientHello of the last attempt got no acknowledgment.
	// It reports whether to dial again, and the error of the dial when not.
	unanswered(destination M.Socksaddr) (again bool, err error)
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

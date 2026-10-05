//go:build with_quic

package v2rayxhttp

import (
	"context"
	"net"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	congestion_meta1 "github.com/sagernet/sing-quic/congestion_meta1"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// quicKeepAlivePeriod is the QUIC keep-alive of an idle HTTP/3 connection
// (Xray's net.QuicgoH3KeepAlivePeriod).
const quicKeepAlivePeriod = 10 * time.Second

// http3Connection carries every request of its sessions as streams of one QUIC
// connection.
type http3Connection struct {
	transport *http3.Transport
	// conns are the QUIC connections dialed: http3.Transport forgets one whose
	// request failed without closing it, and its keep-alive then holds it,
	// its socket and its goroutines open.
	access sync.Mutex
	conns  map[*quic.Conn]struct{}
	closed bool
}

func (c *http3Connection) track(conn *quic.Conn) bool {
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed {
		return false
	}
	if c.conns == nil {
		c.conns = make(map[*quic.Conn]struct{})
	}
	c.conns[conn] = struct{}{}
	context.AfterFunc(conn.Context(), func() {
		c.access.Lock()
		delete(c.conns, conn)
		c.access.Unlock()
	})
	return true
}

func newHTTP3Connections(dialer N.Dialer, serverAddr M.Socksaddr, tlsConfig tls.Config, keepAlivePeriod time.Duration) (func() pooledConnection, error) {
	stdConfig, err := tls.STDConfigForQUIC(tlsConfig)
	if err != nil {
		return nil, E.Cause(err, "xhttp: HTTP/3 TLS")
	}
	stdConfig = stdConfig.Clone()
	stdConfig.NextProtos = []string{http3.NextProtoH3}
	switch {
	case keepAlivePeriod == 0:
		keepAlivePeriod = quicKeepAlivePeriod
	case keepAlivePeriod < 0:
		keepAlivePeriod = 0
	}
	quicConfig := &quic.Config{
		MaxIdleTimeout:          connectionIdleTimeout,
		KeepAlivePeriod:         keepAlivePeriod,
		MaxIncomingStreams:      -1,
		DisablePathMTUDiscovery: !(runtime.GOOS == "linux" || runtime.GOOS == "windows" || runtime.GOOS == "darwin"),
	}
	return func() pooledConnection {
		connection := &http3Connection{}
		connection.transport = &http3.Transport{
			TLSClientConfig: stdConfig,
			QUICConfig:      quicConfig,
			Dial: func(ctx context.Context, addr string, tlsConfig *tls.STDConfig, quicConfig *quic.Config) (*quic.Conn, error) {
				// The connection is shared: the session whose request started
				// the dial must not take it down, by closing, for the sessions
				// waiting for it.
				ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), C.TCPTimeout)
				defer cancel()
				// http3.Transport fills an empty server name from the request's
				// host, which would undo disable_sni.
				tlsConfig = tlsConfig.Clone()
				tlsConfig.ServerName = stdConfig.ServerName
				conn, err := dialer.DialContext(ctx, N.NetworkUDP, serverAddr)
				if err != nil {
					return nil, err
				}
				quicConn, err := quic.DialEarly(ctx, bufio.NewUnbindPacketConn(conn), conn.RemoteAddr(), tlsConfig, quicConfig)
				if err != nil {
					conn.Close()
					return nil, err
				}
				// quic-go does not own a packet conn passed to DialEarly: it
				// only stops reading it when the connection ends.
				context.AfterFunc(quicConn.Context(), func() {
					conn.Close()
				})
				// BBR, as Xray's HTTP/3 uses.
				quicConn.SetCongestionControl(congestion_meta2.NewBbrSender(
					congestion_meta2.DefaultClock{TimeFunc: time.Now},
					congestion.ByteCount(quicConn.Config().InitialPacketSize),
					congestion.ByteCount(congestion_meta1.InitialCongestionWindow),
				))
				if !connection.track(quicConn) {
					quicConn.CloseWithError(0, "")
					return nil, net.ErrClosed
				}
				return quicConn, nil
			},
		}
		return connection
	}, nil
}

func (c *http3Connection) roundTrip(request *http.Request) (*http.Response, error) {
	return c.transport.RoundTrip(request)
}

func (c *http3Connection) close() {
	c.transport.Close()
	c.access.Lock()
	conns := c.conns
	c.conns = nil
	c.closed = true
	c.access.Unlock()
	for conn := range conns {
		conn.CloseWithError(0, "")
	}
}

//go:build with_quic

package v2rayxhttp

import (
	"context"
	"net/http"
	"runtime"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
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
		return &http3Connection{transport: &http3.Transport{
			TLSClientConfig: stdConfig,
			QUICConfig:      quicConfig,
			Dial: func(ctx context.Context, addr string, tlsConfig *tls.STDConfig, quicConfig *quic.Config) (*quic.Conn, error) {
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
				return quicConn, nil
			},
		}}
	}, nil
}

func (c *http3Connection) roundTrip(request *http.Request) (*http.Response, error) {
	return c.transport.RoundTrip(request)
}

func (c *http3Connection) close() {
	c.transport.Close()
}

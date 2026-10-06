package v2ray_test

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

var errTestDial = errors.New("test dialer: no route to host")

// failingDialer counts the dials it is asked for and fails each of them.
type failingDialer struct {
	dials atomic.Int32
}

func (d *failingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	return nil, errTestDial
}

func (d *failingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	d.dials.Add(1)
	return nil, errTestDial
}

type clientTransportCase struct {
	name    string
	options option.V2RayTransportOptions
	// alpn is the ALPN of the TLS the transport runs over; nil is no TLS.
	alpn []string
	// skip, when set, says why the case can't be held this way.
	skip string
}

var clientTransportCases = []clientTransportCase{
	{name: "ws", options: option.V2RayTransportOptions{Type: C.V2RayTransportTypeWebsocket}},
	{name: "httpupgrade", options: option.V2RayTransportOptions{Type: C.V2RayTransportTypeHTTPUpgrade}},
	{name: "http", options: option.V2RayTransportOptions{Type: C.V2RayTransportTypeHTTP}},
	{name: "http, TLS", options: option.V2RayTransportOptions{Type: C.V2RayTransportTypeHTTP}, alpn: []string{}},
	{name: "grpc", options: option.V2RayTransportOptions{Type: C.V2RayTransportTypeGRPC}},
	{name: "grpc, TLS", options: option.V2RayTransportOptions{Type: C.V2RayTransportTypeGRPC}, alpn: []string{}},
	{name: "xhttp", options: option.V2RayTransportOptions{Type: C.V2RayTransportTypeXHTTP}},
	{name: "xhttp, TLS", options: option.V2RayTransportOptions{Type: C.V2RayTransportTypeXHTTP}, alpn: []string{}},
	{name: "xhttp, TLS, HTTP/1.1", options: option.V2RayTransportOptions{Type: C.V2RayTransportTypeXHTTP}, alpn: []string{"http/1.1"}},
	{
		name: "xhttp, TLS, download",
		options: option.V2RayTransportOptions{Type: C.V2RayTransportTypeXHTTP, XHTTPOptions: option.V2RayXHTTPOptions{
			Download: &option.V2RayXHTTPDownloadOptions{
				ServerOptions:               option.ServerOptions{Server: "127.0.0.2", ServerPort: 443},
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true, ServerName: "cdn.example.com"}},
			},
		}},
		alpn: []string{},
	},
}

// Close of a client transport is a reset, not an end: the outbounds call it on
// every change of the network (InterfaceUpdated) and go on dialing through the
// same transport. Whatever the transport keeps between dials, the dial after a
// Close must go out to the server again.
func TestClientTransportCloseIsReset(t *testing.T) {
	for _, c := range clientTransportCases {
		t.Run(c.name, func(t *testing.T) {
			if c.skip != "" {
				t.Skip(c.skip)
			}
			var tlsConfig tls.Config
			if c.alpn != nil {
				var err error
				tlsConfig, err = tls.NewClient(context.Background(), log.StdLogger(), "example.com", option.OutboundTLSOptions{
					Enabled: true, Insecure: true, ServerName: "example.com", ALPN: badoption.Listable[string](c.alpn),
				})
				require.NoError(t, err)
			}
			dialer := new(failingDialer)
			transport, err := v2ray.NewClientTransport(context.Background(), dialer, M.ParseSocksaddr("127.0.0.1:443"), c.options, tlsConfig)
			require.NoError(t, err)
			require.NotNil(t, transport)
			defer transport.Close()
			require.NoError(t, transport.Close(), "before the first dial")
			requireDialReachesServer(t, transport, dialer)
			require.NoError(t, transport.Close())
			require.NoError(t, transport.Close(), "twice in a row")
			requireDialReachesServer(t, transport, dialer)
		})
	}
}

// requireDialReachesServer dials through the transport and expects the failure
// of the dialer back: the transport went to the server, it did not refuse.
func requireDialReachesServer(t *testing.T, transport adapter.V2RayClientTransport, dialer *failingDialer) {
	t.Helper()
	before := dialer.dials.Load()
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := transport.DialContext(ctx)
		if err == nil {
			// The HTTP/2 based transports hand out the connection before the
			// request is on its way: the failure is that of the first read.
			_, err = conn.Read(make([]byte, 1))
			conn.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		require.Error(t, err)
		require.NotErrorIs(t, err, net.ErrClosed)
		require.NotContains(t, err.Error(), net.ErrClosed.Error())
		require.ErrorContains(t, err, errTestDial.Error())
		require.Greater(t, dialer.dials.Load(), before, "the dialer was not asked")
	case <-time.After(15 * time.Second):
		t.Fatal("the dial did not return")
	}
}

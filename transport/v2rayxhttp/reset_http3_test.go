//go:build with_quic

package v2rayxhttp

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// newHTTP3TestPair starts an HTTP/3 test server for the options and a client
// of it.
func newHTTP3TestPair(t *testing.T, options option.V2RayXHTTPOptions) *Client {
	t.Helper()
	serverConfig, err := newRequestConfig(options.V2RayXHTTPBaseOptions, options.Mode)
	require.NoError(t, err)
	handler := &testServer{t: t, config: serverConfig, sessions: make(map[string]*testSession), requests: make(map[string]int)}
	// httptest only provides the certificate here.
	certificateServer := httptest.NewUnstartedServer(nil)
	certificateServer.StartTLS()
	serverTLS := certificateServer.TLS.Clone()
	certificateServer.Close()
	serverTLS.NextProtos = []string{http3.NextProtoH3}
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &http3.Server{Handler: http.HandlerFunc(handler.serveHTTP), TLSConfig: serverTLS}
	go server.Serve(packetConn)
	t.Cleanup(func() {
		server.Close()
		packetConn.Close()
	})
	tlsConfig, err := tls.NewClient(context.Background(), log.StdLogger(), "example.com", option.OutboundTLSOptions{
		Enabled: true, Insecure: true, ServerName: "example.com", ALPN: badoption.Listable[string]{"h3"},
	})
	require.NoError(t, err)
	transport, err := NewClient(context.Background(), N.SystemDialer, M.SocksaddrFromNet(packetConn.LocalAddr()), options, tlsConfig)
	require.NoError(t, err)
	client := transport.(*Client)
	t.Cleanup(func() { client.Close() })
	return client
}

// A reset over HTTP/3: the QUIC connections of every lane are closed and the
// next dial opens new ones.
func TestXHTTPResetHTTP3(t *testing.T) {
	for _, mode := range []string{modePacketUp, modeStreamUp, modeStreamOne} {
		t.Run(mode, func(t *testing.T) {
			options := option.V2RayXHTTPOptions{Mode: mode}
			options.Path = "/h3"
			testReset(t, newHTTP3TestPair(t, options))
		})
	}
}

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

// tls.alpn ["h3"] selects HTTP/3, every mode over QUIC streams.
func TestXHTTPHTTP3(t *testing.T) {
	testHTTP3(t, false)
}

// A request the server resets must not leave its QUIC connection behind:
// http3.Transport forgets such a connection without closing it.
func TestXHTTPHTTP3ResetLeavesNothing(t *testing.T) {
	testHTTP3(t, true)
}

func testHTTP3(t *testing.T, abortUploads bool) {
	modes := []string{modePacketUp, modeStreamUp, modeStreamOne}
	if abortUploads {
		modes = []string{modePacketUp, modeStreamUp}
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			options := option.V2RayXHTTPOptions{Mode: mode}
			options.Path = "/h3"
			serverConfig, err := newRequestConfig(options.V2RayXHTTPBaseOptions, mode)
			require.NoError(t, err)
			handler := &testServer{t: t, config: serverConfig, sessions: make(map[string]*testSession), requests: make(map[string]int), abortUploads: abortUploads}
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
			baseline := settledGoroutines()
			for i := 0; i < 3; i++ {
				conn, err := transport.DialContext(context.Background())
				if abortUploads && err != nil {
					// the pool backs off after the resets
					continue
				}
				require.NoError(t, err)
				if abortUploads {
					conn.Write([]byte("x"))
					conn.Read(make([]byte, 1))
				} else {
					echo(t, conn, 128*1024)
				}
				conn.Close()
			}
			transport.Close()
			waitGoroutines(t, baseline)
			require.Zero(t, handler.requestCount("bad-padding"))
		})
	}
}

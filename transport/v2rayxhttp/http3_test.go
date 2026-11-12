//go:build with_quic

package v2rayxhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

// More sessions than one QUIC connection has streams for: the server allows
// 100 at a time by quic-go's default, and the sessions past them must get a
// connection of their own instead of waiting for a stream.
func TestXHTTPHTTP3StreamLimit(t *testing.T) {
	options := option.V2RayXHTTPOptions{Mode: modeStreamOne}
	options.Path = "/h3"
	// one pooled connection, so that the lanes are what carries the excess
	options.Xmux = &option.V2RayXHTTPXmuxOptions{MaxConnections: &option.V2RayXHTTPRange{From: 1, To: 1}}
	serverConfig, err := newRequestConfig(options.V2RayXHTTPBaseOptions, modeStreamOne)
	require.NoError(t, err)
	handler := &testServer{t: t, config: serverConfig, sessions: make(map[string]*testSession), requests: make(map[string]int)}
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
	const sessions = 250
	conns := make([]net.Conn, 0, sessions)
	for i := 0; i < sessions; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := transport.DialContext(ctx)
		cancel()
		require.NoError(t, err, "session %d", i)
		conns = append(conns, conn)
	}
	// every one of them carries data while all are open
	for i, conn := range conns {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		message := []byte{byte(i), byte(i >> 8), 7}
		_, err = conn.Write(message)
		require.NoError(t, err, "session %d", i)
		reply := make([]byte, len(message))
		done := make(chan error, 1)
		go func() {
			_, err := io.ReadFull(conn, reply)
			done <- err
		}()
		select {
		case err = <-done:
			require.NoError(t, err, "session %d", i)
			require.Equal(t, message, reply)
		case <-time.After(10 * time.Second):
			t.Fatalf("session %d got no stream", i)
		}
	}
	connection := transport.(*Client).upPool.clients[0].connection.(*http3Connection)
	connection.access.Lock()
	lanes := len(connection.lanes)
	connection.access.Unlock()
	require.Equal(t, 3, lanes, "250 sessions, 90 to a QUIC connection")
	for _, conn := range conns {
		conn.Close()
	}
	transport.Close()
	waitGoroutines(t, baseline)
}

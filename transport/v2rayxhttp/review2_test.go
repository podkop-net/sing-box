//go:build with_quic

package v2rayxhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A server that reads every packet-up request and holds its answer, as Xray
// does with its upload queue full (the destination reads nothing): what the
// client keeps of the session must stay bounded, and a closed session must
// let go of its connection.
func TestXHTTPUnansweredPosts(t *testing.T) {
	options := option.V2RayXHTTPOptions{Mode: modePacketUp}
	serverConfig, err := newRequestConfig(options.V2RayXHTTPBaseOptions, modePacketUp)
	require.NoError(t, err)
	inner := &testServer{t: t, config: serverConfig, sessions: make(map[string]*testSession), requests: make(map[string]int)}
	release := make(chan struct{})
	var held atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, seq := inner.meta(r); seq != "" {
			n, _ := io.Copy(io.Discard, r.Body)
			held.Add(n)
			select {
			case <-release:
				w.WriteHeader(http.StatusOK)
			case <-r.Context().Done():
			}
			return
		}
		inner.serveHTTP(w, r)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	tlsConfig, err := tls.NewClient(context.Background(), log.StdLogger(), "example.com", option.OutboundTLSOptions{Enabled: true, Insecure: true, ServerName: "example.com"})
	require.NoError(t, err)
	transport, err := NewClient(context.Background(), N.SystemDialer, M.ParseSocksaddr(server.Listener.Addr().String()), options, tlsConfig)
	require.NoError(t, err)
	client := transport.(*Client)
	t.Cleanup(func() { client.Close() })
	require.True(t, client.upPool.watched)

	conn, err := client.DialContext(context.Background())
	require.NoError(t, err)
	uploader := conn.(*session).packetUpload
	const total = 48 << 20
	var written atomic.Int64
	writeDone := make(chan error, 1)
	go func() {
		chunk := make([]byte, 64<<10)
		for written.Load() < total {
			n, err := conn.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()
	select {
	case err = <-writeDone:
		t.Logf("all %d MiB accepted with no answer to any request, write error: %v", written.Load()>>20, err)
	case <-time.After(3 * time.Second):
		t.Logf("writes wait after %d MiB", written.Load()>>20)
	}
	time.Sleep(500 * time.Millisecond)
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	t.Logf("request size %d, requests in flight %d, server holds %d MiB, heap in use %d MiB",
		uploader.maxSize, uploader.inFlight.Load(), held.Load()>>20, stats.HeapInuse>>20)
	assert.LessOrEqual(t, int(uploader.inFlight.Load()), 8, "unanswered requests of one session, a megabyte each")

	// the session is closed: after the linger nothing of it should hold the
	// pooled connection
	require.NoError(t, conn.Close())
	time.Sleep(closeLinger + closeGrace + time.Second)
	client.upPool.access.Lock()
	var running int32
	for _, pooled := range client.upPool.clients {
		running += pooled.running.Load()
	}
	for pooled := range client.upPool.retired {
		running += pooled.running.Load()
	}
	client.upPool.access.Unlock()
	t.Logf("%d s after Close: running count %d, requests in flight %d", int((closeLinger + closeGrace + time.Second).Seconds()), running, uploader.inFlight.Load())
	assert.Zero(t, running, "requests of a closed session still hold the connection")
	close(release)
	require.Eventually(t, func() bool { return uploader.inFlight.Load() == 0 }, 10*time.Second, 20*time.Millisecond)
}

// A dial given up before the server answered wrote nothing: the session has
// nothing to linger for.
func TestXHTTPGivenUpDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	var (
		access   sync.Mutex
		accepted []net.Conn
	)
	t.Cleanup(func() {
		access.Lock()
		defer access.Unlock()
		for _, conn := range accepted {
			conn.Close()
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// accepted, never answered
			access.Lock()
			accepted = append(accepted, conn)
			access.Unlock()
		}
	}()
	for _, mode := range []string{modePacketUp, modeStreamUp, modeStreamOne} {
		t.Run(mode, func(t *testing.T) {
			tlsConfig, err := tls.NewClient(context.Background(), log.StdLogger(), "example.com", option.OutboundTLSOptions{Enabled: true, Insecure: true, ServerName: "example.com"})
			require.NoError(t, err)
			transport, err := NewClient(context.Background(), N.SystemDialer, M.ParseSocksaddr(listener.Addr().String()), option.V2RayXHTTPOptions{Mode: mode}, tlsConfig)
			require.NoError(t, err)
			client := transport.(*Client)
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			_, err = client.DialContext(ctx)
			require.Error(t, err)
			time.Sleep(time.Second)
			client.upPool.access.Lock()
			var running, sessions int32
			for _, pooled := range client.upPool.clients {
				running += pooled.running.Load()
				sessions += pooled.sessions.Load()
			}
			client.upPool.access.Unlock()
			assert.Zero(t, running, "running count a second after the dial was given up")
			assert.Zero(t, sessions, "session count a second after the dial was given up")
		})
	}
}

// Closing the client while a QUIC connection is being dialed to a server that
// does not answer.
func TestXHTTPHTTP3CloseDuringDial(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { packetConn.Close() })
	tlsConfig, err := tls.NewClient(context.Background(), log.StdLogger(), "example.com", option.OutboundTLSOptions{
		Enabled: true, Insecure: true, ServerName: "example.com", ALPN: badoption.Listable[string]{"h3"},
	})
	require.NoError(t, err)
	transport, err := NewClient(context.Background(), N.SystemDialer, M.SocksaddrFromNet(packetConn.LocalAddr()), option.V2RayXHTTPOptions{Mode: modePacketUp}, tlsConfig)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err = transport.DialContext(ctx)
	require.Error(t, err)
	start := time.Now()
	transport.Close()
	elapsed := time.Since(start)
	t.Logf("Client.Close took %s", elapsed.Round(10*time.Millisecond))
	assert.Less(t, elapsed, time.Second, "Close waits for the dial")
}

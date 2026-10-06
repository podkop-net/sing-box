package v2rayxhttp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// testReset holds the contract of adapter.V2RayClientTransport for Close: it
// is a reset. The outbounds call it whenever the network changed and go on
// dialing through the same transport. The sessions open at the time fail with
// their connections, the next dial opens new ones, what the closed connections
// report afterwards is not held against the server, and nothing is left behind.
func testReset(t *testing.T, client *Client) {
	t.Helper()
	baseline := settledGoroutines()
	dial := func() net.Conn {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := client.DialContext(ctx)
		require.NoError(t, err)
		return conn
	}
	// as many sessions as the pool has connections by default: two failed
	// connections in a row are what starts a backoff
	old := make([]net.Conn, 3)
	for i := range old {
		old[i] = dial()
		echo(t, old[i], 4096)
	}
	require.NoError(t, client.Close())
	for i, conn := range old {
		done := make(chan error, 1)
		go func() {
			conn.Write([]byte("x"))
			_, err := io.ReadFull(conn, make([]byte, 1))
			done <- err
		}()
		select {
		case err := <-done:
			require.Error(t, err, "session %d went on after the reset", i)
		case <-time.After(5 * time.Second):
			t.Fatalf("session %d outlived the reset", i)
		}
	}
	for i := 0; i < 3; i++ {
		conn := dial()
		echo(t, conn, 64*1024)
		require.NoError(t, conn.Close())
	}
	for _, conn := range old {
		conn.Close()
	}
	requireNoBackoff(t, client)
	// any number of times, with nothing open as well
	require.NoError(t, client.Close())
	require.NoError(t, client.Close())
	waitGoroutines(t, baseline)
	conn := dial()
	echo(t, conn, 4096)
	require.NoError(t, conn.Close())
	requireNoBackoff(t, client)
	require.NoError(t, client.Close())
	waitGoroutines(t, baseline)
}

func dialContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func requireNoBackoff(t *testing.T, client *Client) {
	t.Helper()
	for _, p := range []*pool{client.upPool, client.downPool} {
		p.access.Lock()
		failures, retryAt, lastErr := p.failures, p.retryAt, p.lastErr
		p.access.Unlock()
		require.Zero(t, failures)
		require.True(t, retryAt.IsZero(), "the pool backs off")
		require.NoError(t, lastErr)
	}
}

func TestXHTTPReset(t *testing.T) {
	cases := []struct {
		mode    string
		version string
	}{
		{modePacketUp, "h2"},
		{modeStreamUp, "h2"},
		{modeStreamOne, "h2"},
		{modePacketUp, "h1-tls"},
		{modePacketUp, "h1"},
		{modeStreamUp, "h1"},
	}
	for _, c := range cases {
		t.Run(c.mode+"/"+c.version, func(t *testing.T) {
			client, _ := newTestPair(t, option.V2RayXHTTPOptions{Mode: c.mode}, c.version, nil)
			testReset(t, client)
		})
	}
}

// newDownloadTestPair is newTestPair with the download half sent to a second
// listener of the same test server, over a pool of its own.
func newDownloadTestPair(t *testing.T, mode string) *Client {
	t.Helper()
	options := option.V2RayXHTTPOptions{Mode: mode}
	options.Path = "/x"
	serverConfig, err := newRequestConfig(options.V2RayXHTTPBaseOptions, mode)
	require.NoError(t, err)
	server := newTestServer(t, serverConfig, "h2")
	second := httptest.NewUnstartedServer(http.HandlerFunc(server.serveHTTP))
	second.EnableHTTP2 = true
	second.StartTLS()
	t.Cleanup(second.Close)
	secondAddr := M.ParseSocksaddr(second.Listener.Addr().String())
	options.Download = &option.V2RayXHTTPDownloadOptions{
		ServerOptions:               option.ServerOptions{Server: secondAddr.AddrString(), ServerPort: secondAddr.Port},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true, ServerName: "cdn.example.com"}},
	}
	options.Download.Path = "/x"
	tlsConfig, err := tls.NewClient(context.Background(), log.StdLogger(), "example.com", option.OutboundTLSOptions{Enabled: true, Insecure: true, ServerName: "example.com"})
	require.NoError(t, err)
	transport, err := NewClient(context.Background(), N.SystemDialer, M.ParseSocksaddr(server.server.Listener.Addr().String()), options, tlsConfig)
	require.NoError(t, err)
	client := transport.(*Client)
	t.Cleanup(func() { client.Close() })
	require.NotSame(t, client.upPool, client.downPool)
	return client
}

// With download set there are two pools, and a reset is one of both.
func TestXHTTPResetDownloadLeg(t *testing.T) {
	for _, mode := range []string{modePacketUp, modeStreamUp} {
		t.Run(mode, func(t *testing.T) {
			testReset(t, newDownloadTestPair(t, mode))
		})
	}
}

// A reset forgets what the pool held against the server, and the failures the
// connections it closed report later do not count against the new ones: the
// first dial on the new network must not meet the backoff of the old one.
func TestXHTTPResetForgetsFailures(t *testing.T) {
	options := option.V2RayXHTTPOptions{Mode: modePacketUp}
	options.Xmux = &option.V2RayXHTTPXmuxOptions{MaxConnections: xrange(4, 4)}
	client, _ := newTestPair(t, options, "h2", nil)
	held := make([]*poolClient, 4)
	for i := range held {
		var err error
		held[i], err = client.upPool.get(true)
		require.NoError(t, err)
	}
	unreachable := errors.New("network is unreachable")
	held[0].fail(context.Background(), unreachable)
	held[1].fail(context.Background(), unreachable)
	client.upPool.access.Lock()
	retryAt := client.upPool.retryAt
	client.upPool.access.Unlock()
	require.False(t, retryAt.IsZero(), "two young connections failed: the pool backs off")
	require.NoError(t, client.Close())
	requireNoBackoff(t, client)
	held[2].fail(context.Background(), unreachable)
	held[3].fail(context.Background(), unreachable)
	requireNoBackoff(t, client)
	conn, err := client.DialContext(dialContext(t))
	require.NoError(t, err)
	echo(t, conn, 4096)
	require.NoError(t, conn.Close())
	for _, c := range held {
		c.endSession()
		c.release()
	}
	client.upPool.access.Lock()
	retired := len(client.upPool.retired)
	client.upPool.access.Unlock()
	require.Zero(t, retired, "the connections the reset closed are still listed")
}

// Resets while sessions are dialed, used and closed: nothing races, hangs or
// stays behind, and the transport works once they are over.
func TestXHTTPResetDuringDials(t *testing.T) {
	for _, version := range []string{"h2", "h1"} {
		t.Run(version, func(t *testing.T) {
			client, _ := newTestPair(t, option.V2RayXHTTPOptions{Mode: modePacketUp}, version, nil)
			baseline := settledGoroutines()
			stop := make(chan struct{})
			var wg sync.WaitGroup
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-stop:
							return
						default:
						}
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						conn, err := client.DialContext(ctx)
						cancel()
						if err != nil {
							time.Sleep(time.Millisecond)
							continue
						}
						// either may fail: the session may have been reset
						conn.Write(randomBytes(1000))
						io.ReadFull(conn, make([]byte, 1000))
						conn.Close()
					}
				}()
			}
			for i := 0; i < 50; i++ {
				time.Sleep(20 * time.Millisecond)
				client.Close()
			}
			close(stop)
			wg.Wait()
			client.Close()
			conn, err := client.DialContext(dialContext(t))
			require.NoError(t, err)
			echo(t, conn, 4096)
			require.NoError(t, conn.Close())
			client.Close()
			waitGoroutines(t, baseline)
		})
	}
}

// The transport ends with the context it was created with: once that is done
// a dial is refused, so that one racing with the last Close leaves nothing.
func TestXHTTPDialAfterContextDone(t *testing.T) {
	options := option.V2RayXHTTPOptions{Mode: modePacketUp}
	_, server := newTestPair(t, options, "h2", nil)
	tlsConfig, err := tls.NewClient(context.Background(), log.StdLogger(), "example.com", option.OutboundTLSOptions{Enabled: true, Insecure: true, ServerName: "example.com"})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	transport, err := NewClient(ctx, N.SystemDialer, M.ParseSocksaddr(server.server.Listener.Addr().String()), options, tlsConfig)
	require.NoError(t, err)
	client := transport.(*Client)
	baseline := settledGoroutines()
	conn, err := client.DialContext(dialContext(t))
	require.NoError(t, err)
	echo(t, conn, 4096)
	require.NoError(t, conn.Close())
	cancel()
	require.NoError(t, client.Close())
	_, err = client.DialContext(dialContext(t))
	require.ErrorIs(t, err, net.ErrClosed)
	client.upPool.access.Lock()
	pooled := len(client.upPool.clients)
	client.upPool.access.Unlock()
	require.Zero(t, pooled)
	waitGoroutines(t, baseline)
}

// countingConnection is a pooled connection that only counts its requests.
type countingConnection struct {
	requests atomic.Int32
}

func (c *countingConnection) roundTrip(request *http.Request) (*http.Response, error) {
	c.requests.Add(1)
	return nil, errors.New("no server")
}

func (c *countingConnection) close() {}

// A session that outlives a reset may send one more request through the client
// it holds. The request is refused before it reaches the HTTP client, which
// would dial the server for it, and says nothing about the server.
func TestXHTTPResetRefusesRequestsOfClosedClients(t *testing.T) {
	connection := new(countingConnection)
	p := newPool(context.Background(), xmuxConfig{}, func() pooledConnection { return connection })
	client, err := p.get(true)
	require.NoError(t, err)
	request, err := http.NewRequest(http.MethodPost, "http://example.com/", nil)
	require.NoError(t, err)
	_, err = client.roundTrip(request)
	require.Error(t, err)
	require.EqualValues(t, 1, connection.requests.Load())
	p.close()
	_, err = client.roundTrip(request)
	require.ErrorIs(t, err, net.ErrClosed)
	require.EqualValues(t, 1, connection.requests.Load(), "a request went out through a closed client")
	client.endSession()
	client.release()
	// the same for a client retired in the ordinary way
	client, err = p.get(true)
	require.NoError(t, err)
	client.endSession()
	client.release()
	p.retire(client)
	_, err = client.roundTrip(request)
	require.ErrorIs(t, err, net.ErrClosed)
	require.EqualValues(t, 1, connection.requests.Load())
	p.access.Lock()
	failures := p.failures
	p.access.Unlock()
	require.Zero(t, failures)
}

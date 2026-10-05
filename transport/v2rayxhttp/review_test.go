package v2rayxhttp

import (
	"context"
	"math"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// A range as wide as int32 used to panic in rand: `sing-box check` for the
// XMUX pool sizes, the running process for the rest.
func TestXHTTPWideRanges(t *testing.T) {
	for _, r := range []valueRange{{0, math.MaxInt32}, {-1, math.MaxInt32}, {math.MinInt32, math.MaxInt32}, {math.MinInt32, 0}, {5, 5}, {7, 3}} {
		for i := 0; i < 100; i++ {
			value := r.rand()
			if r.to > r.from {
				require.True(t, value >= r.from && value <= r.to, "%v gave %d", r, value)
			}
		}
	}
	wide := xrange(0, math.MaxInt32)
	options := option.V2RayXHTTPOptions{Mode: modePacketUp}
	options.ScMinPostsIntervalMs = xrange(-1, -1)
	options.Xmux = &option.V2RayXHTTPXmuxOptions{MaxConnections: wide, CMaxReuseTimes: wide, HMaxRequestTimes: wide, HMaxReusableSecs: wide}
	client, _ := newTestPair(t, options, "h2", nil)
	conn, err := client.DialContext(context.Background())
	require.NoError(t, err)
	echo(t, conn, 4096)
	conn.Close()
}

func TestXHTTPIPv6Host(t *testing.T) {
	transport, err := NewClient(context.Background(), N.SystemDialer, M.ParseSocksaddr("[2001:db8::5]:443"), option.V2RayXHTTPOptions{}, nil)
	require.NoError(t, err)
	defer transport.Close()
	client := transport.(*Client)
	require.Equal(t, "[2001:db8::5]", client.up.host)
	request := client.up.newStreamRequest(context.Background(), "http", "id", nil)
	require.Equal(t, "[2001:db8::5]", request.Host)
	require.Contains(t, request.Header.Get("Referer"), "http://[2001:db8::5]/?x_padding=")
}

// max_concurrency counts sessions, once each, as Xray does: not the requests
// a session has in flight.
func TestXHTTPConcurrencyCountsSessions(t *testing.T) {
	for _, mode := range []string{modePacketUp, modeStreamUp, modeStreamOne} {
		t.Run(mode, func(t *testing.T) {
			options := option.V2RayXHTTPOptions{Mode: mode}
			options.Xmux = &option.V2RayXHTTPXmuxOptions{MaxConcurrency: xrange(2, 2)}
			client, _ := newTestPair(t, options, "h2", nil)
			var conns []net.Conn
			for i := 0; i < 4; i++ {
				conn, err := client.DialContext(context.Background())
				require.NoError(t, err)
				echo(t, conn, 1024)
				conns = append(conns, conn)
			}
			client.upPool.access.Lock()
			clients := len(client.upPool.clients)
			client.upPool.access.Unlock()
			require.Equal(t, 2, clients, "four sessions, two to a connection")
			for _, conn := range conns {
				conn.Close()
			}
			// a closed session is gone once its upload has been sent to the end
			require.Eventually(t, func() bool {
				client.upPool.access.Lock()
				defer client.upPool.access.Unlock()
				for _, pooled := range client.upPool.clients {
					if pooled.sessions.Load() != 0 {
						return false
					}
				}
				return true
			}, 2*time.Second, 5*time.Millisecond)
		})
	}
}

// The body of an error answer may never end: the session fails at once.
func TestXHTTPErrorStatusWithEndlessBody(t *testing.T) {
	client, _ := newTestPair(t, option.V2RayXHTTPOptions{Mode: modePacketUp}, "h2", func(s *testServer) {
		s.downloadStatus, s.endlessErrorBody = http.StatusForbidden, true
	})
	conn, err := client.DialContext(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		done <- err
	}()
	select {
	case err = <-done:
		require.ErrorContains(t, err, "403")
	case <-time.After(3 * time.Second):
		t.Fatal("read still waits for the body of the error answer")
	}
}

// A download detour that leads back to its own outbound must not dial itself
// without end.
func TestXHTTPDialDepth(t *testing.T) {
	client, _ := newTestPair(t, option.V2RayXHTTPOptions{Mode: modePacketUp}, "h2", nil)
	ctx := context.Background()
	for i := 0; i < maxDialDepth; i++ {
		s := newSession(dialDepth(ctx))
		ctx = s.ctx
		defer s.Close()
	}
	_, err := client.DialContext(ctx)
	require.ErrorContains(t, err, "leads back")
}

// Closing the transport closes the connections retired from the pool that a
// session still holds.
func TestXHTTPCloseReachesRetiredClients(t *testing.T) {
	options := option.V2RayXHTTPOptions{Mode: modeStreamOne}
	options.Xmux = &option.V2RayXHTTPXmuxOptions{MaxConnections: xrange(1, 1), HMaxRequestTimes: xrange(1, 1)}
	client, _ := newTestPair(t, options, "h2", nil)
	first, err := client.DialContext(context.Background())
	require.NoError(t, err)
	echo(t, first, 1024)
	second, err := client.DialContext(context.Background())
	require.NoError(t, err)
	echo(t, second, 1024)
	client.Close()
	first.SetDeadline(time.Time{})
	done := make(chan error, 1)
	go func() {
		first.Write([]byte("x"))
		_, err := first.Read(make([]byte, 1))
		done <- err
	}()
	select {
	case err = <-done:
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("a session on a retired connection outlived the transport")
	}
	second.Close()
	first.Close()
}

// An upload whose headers are larger than the server takes fails its own
// session, with the setting named, and nothing else: the connection stays in
// service and other sessions of the outbound are not made to wait.
func TestXHTTPHeadersTooLarge(t *testing.T) {
	size := option.V2RayXHTTPRange{From: 16384, To: 16384}
	options := option.V2RayXHTTPOptions{Mode: modePacketUp, V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{
		UplinkDataPlacement: placementHeader,
		ScMaxEachPostBytes:  &size,
	}}
	for name, test := range map[string]struct {
		version   string
		configure func(*testServer)
	}{
		// the HTTP/2 client refuses to send the request
		"advertised limit": {"h2-8k", nil},
		// a proxy that does not announce its limit answers
		"status 431": {"h2", func(s *testServer) { s.maxPacket = 6000 }},
	} {
		t.Run(name, func(t *testing.T) {
			client, server := newTestPair(t, options, test.version, test.configure)
			for round := 0; round < 3; round++ {
				conn, err := client.DialContext(context.Background())
				require.NoError(t, err, "round %d", round)
				_, err = conn.Write(randomBytes(16384))
				if err == nil {
					_, err = conn.Read(make([]byte, 1))
				}
				require.ErrorContains(t, err, "sc_max_each_post_bytes")
				conn.Close()
			}
			// small uploads of other sessions pass at once, through the same connection
			connections := server.connections()
			for i := 0; i < 5; i++ {
				conn, err := client.DialContext(context.Background())
				require.NoError(t, err)
				echo(t, conn, 1000)
				conn.Close()
			}
			require.Equal(t, connections, server.connections())
		})
	}
}

// What was written before a Close reaches the server: sing-box closes the
// connection as soon as its source is done.
func TestXHTTPWriteThenClose(t *testing.T) {
	for _, version := range []string{"h2", "h1-tls"} {
		for _, mode := range []string{modePacketUp, modeStreamUp, modeStreamOne} {
			if mode == modeStreamOne && version != "h2" {
				continue
			}
			for _, size := range []int{100, 5000, 300000} {
				t.Run(F.ToString(version, "/", mode, "/", size), func(t *testing.T) {
					client, server := newTestPair(t, option.V2RayXHTTPOptions{Mode: mode}, version, nil)
					baseline := settledGoroutines()
					const sessions = 10
					for i := 0; i < sessions; i++ {
						conn, err := client.DialContext(context.Background())
						require.NoError(t, err)
						_, err = conn.Write(randomBytes(size))
						require.NoError(t, err)
						require.NoError(t, conn.Close())
						_, err = conn.Write([]byte{0})
						require.ErrorIs(t, err, net.ErrClosed)
					}
					require.Eventually(t, func() bool { return server.received.Load() == int64(sessions*size) },
						5*time.Second, 10*time.Millisecond, "the server got %d of %d bytes", server.received.Load(), sessions*size)
					// and the closed sessions leave nothing behind, once the
					// connections of the pool are closed too
					client.Close()
					waitGoroutines(t, baseline)
				})
			}
		}
	}
}

// A closed session whose data cannot be sent is gone after the linger at most,
// and at once when it has failed.
func TestXHTTPCloseDoesNotWaitForAFailedSession(t *testing.T) {
	client, _ := newTestPair(t, option.V2RayXHTTPOptions{Mode: modePacketUp}, "h2", func(s *testServer) { s.abortUploads = true })
	baseline := settledGoroutines()
	conn, err := client.DialContext(context.Background())
	require.NoError(t, err)
	_, err = conn.Write(randomBytes(1000))
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	client.Close()
	waitGoroutines(t, baseline)
}

// The backoff holds back new connections, not the sessions a working
// connection can take: one user's request that makes a proxy drop connections
// must not cut the outbound off for everyone.
func TestXHTTPBackoffKeepsWorkingConnections(t *testing.T) {
	client, _ := newTestPair(t, option.V2RayXHTTPOptions{Mode: modePacketUp}, "h2", nil)
	// a working connection, held by an open session
	held, err := client.DialContext(context.Background())
	require.NoError(t, err)
	defer held.Close()
	echo(t, held, 100)
	// the pool in backoff, as after two young connections failed
	client.upPool.access.Lock()
	client.upPool.failures = 2
	client.upPool.lastErr = E.New("test")
	client.upPool.retryAt = time.Now().Add(time.Minute)
	clients := len(client.upPool.clients)
	client.upPool.access.Unlock()
	require.Equal(t, 1, clients)
	for i := 0; i < 5; i++ {
		conn, err := client.DialContext(context.Background())
		require.NoError(t, err)
		echo(t, conn, 100)
		conn.Close()
	}
	client.upPool.access.Lock()
	clients = len(client.upPool.clients)
	client.upPool.access.Unlock()
	require.Equal(t, 1, clients, "no new connection during the backoff")
}

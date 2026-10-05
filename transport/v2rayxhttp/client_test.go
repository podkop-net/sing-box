package v2rayxhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// newTestPair starts a test server for the options and a client of it.
// version is "h2" (TLS), "h1-tls" or "h1" (cleartext).
func newTestPair(t *testing.T, options option.V2RayXHTTPOptions, version string, configure func(*testServer)) (*Client, *testServer) {
	t.Helper()
	mode := options.Mode
	if mode == "" {
		mode = modeAuto
	}
	serverConfig, err := newRequestConfig(options.V2RayXHTTPBaseOptions, mode)
	require.NoError(t, err)
	server := newTestServer(t, serverConfig, version)
	if configure != nil {
		configure(server)
	}
	var tlsConfig tls.Config
	if version != "h1" {
		tlsOptions := option.OutboundTLSOptions{Enabled: true, Insecure: true, ServerName: "example.com"}
		if version == "h1-tls" {
			tlsOptions.ALPN = badoption.Listable[string]{"http/1.1"}
		}
		tlsConfig, err = tls.NewClient(context.Background(), log.StdLogger(), "example.com", tlsOptions)
		require.NoError(t, err)
	}
	transport, err := NewClient(context.Background(), N.SystemDialer, M.ParseSocksaddr(server.server.Listener.Addr().String()), options, tlsConfig)
	require.NoError(t, err)
	client := transport.(*Client)
	t.Cleanup(func() { client.Close() })
	return client, server
}

func randomBytes(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

// echo writes size bytes in uneven pieces and reads them back from the server.
func echo(t *testing.T, conn net.Conn, size int) {
	t.Helper()
	data := randomBytes(size)
	writeErr := make(chan error, 1)
	go func() {
		pieces := []int{1, 7, 1500, 16 * 1024, 64 * 1024}
		for i, offset := 0, 0; offset < len(data); i++ {
			end := min(offset+pieces[i%len(pieces)], len(data))
			if _, err := conn.Write(data[offset:end]); err != nil {
				writeErr <- err
				return
			}
			offset = end
		}
		writeErr <- nil
	}()
	received := make([]byte, size)
	_, err := io.ReadFull(conn, received)
	require.NoError(t, err)
	require.NoError(t, <-writeErr)
	require.True(t, bytes.Equal(data, received), "echoed data differs")
}

// settledGoroutines is the goroutine count once servers started in the
// background have finished starting theirs.
func settledGoroutines() int {
	count := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		next := runtime.NumGoroutine()
		if next == count {
			return count
		}
		count = next
	}
	return count
}

// waitGoroutines waits for the goroutines to come back to the count before a
// test, so that every request, reader and uploader a session started is known
// to have ended.
func waitGoroutines(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline {
		if time.Now().After(deadline) {
			buffer := make([]byte, 1<<20)
			n := runtime.Stack(buffer, true)
			t.Fatalf("%d goroutines left over (baseline %d):\n%s", runtime.NumGoroutine(), baseline, buffer[:n])
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestXHTTPModes(t *testing.T) {
	cases := []struct {
		mode    string
		version string
	}{
		{modePacketUp, "h1"},
		{modePacketUp, "h1-tls"},
		{modePacketUp, "h2"},
		{modeStreamUp, "h1"},
		{modeStreamUp, "h1-tls"},
		{modeStreamUp, "h2"},
		{modeStreamOne, "h2"},
		{modeAuto, "h2"},
	}
	for _, c := range cases {
		t.Run(c.mode+"/"+c.version, func(t *testing.T) {
			options := option.V2RayXHTTPOptions{Mode: c.mode}
			options.Path = "/xhttp"
			client, server := newTestPair(t, options, c.version, nil)
			baseline := runtime.NumGoroutine()
			var wg sync.WaitGroup
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					conn, err := client.DialContext(context.Background())
					if !assertNoError(t, err) {
						return
					}
					echo(t, conn, 256*1024)
					conn.Close()
				}()
			}
			wg.Wait()
			client.Close()
			waitGoroutines(t, baseline)
			require.Zero(t, server.requestCount("bad-padding"))
			require.Zero(t, server.requestCount("not-found"))
		})
	}
}

func assertNoError(t *testing.T, err error) bool {
	if err != nil {
		t.Error(err)
		return false
	}
	return true
}

func TestXHTTPPlacements(t *testing.T) {
	cases := map[string]func(*option.V2RayXHTTPBaseOptions){
		"session and seq in query": func(o *option.V2RayXHTTPBaseOptions) {
			o.SessionPlacement, o.SeqPlacement = placementQuery, placementQuery
		},
		"session and seq in headers": func(o *option.V2RayXHTTPBaseOptions) {
			o.SessionPlacement, o.SeqPlacement, o.SessionKey = placementHeader, placementHeader, "X-Upload-Token"
		},
		"session and seq in cookies": func(o *option.V2RayXHTTPBaseOptions) {
			o.SessionPlacement, o.SeqPlacement = placementCookie, placementCookie
		},
		"data in headers": func(o *option.V2RayXHTTPBaseOptions) {
			o.UplinkDataPlacement = placementHeader
		},
		"data in cookies with GET": func(o *option.V2RayXHTTPBaseOptions) {
			o.UplinkDataPlacement, o.UplinkHTTPMethod = placementCookie, "get"
		},
		"padding obfs tokenish in header": func(o *option.V2RayXHTTPBaseOptions) {
			o.XPaddingObfsMode, o.XPaddingPlacement, o.XPaddingMethod = true, placementHeader, paddingMethodTokenish
		},
		"padding obfs in cookie": func(o *option.V2RayXHTTPBaseOptions) {
			o.XPaddingObfsMode, o.XPaddingPlacement = true, placementCookie
		},
		"padding obfs in query": func(o *option.V2RayXHTTPBaseOptions) {
			o.XPaddingObfsMode, o.XPaddingPlacement, o.XPaddingKey = true, placementQuery, "pad"
		},
		"session table and path query": func(o *option.V2RayXHTTPBaseOptions) {
			o.SessionIDTable, o.SessionIDLength = "Base62", &option.V2RayXHTTPRange{From: 16, To: 24}
			o.Path = "/api/v1?client=web"
		},
	}
	for name, configure := range cases {
		t.Run(name, func(t *testing.T) {
			options := option.V2RayXHTTPOptions{Mode: modePacketUp}
			options.Path = "/up"
			configure(&options.V2RayXHTTPBaseOptions)
			client, server := newTestPair(t, options, "h2", nil)
			conn, err := client.DialContext(context.Background())
			require.NoError(t, err)
			echo(t, conn, 64*1024)
			conn.Close()
			require.Zero(t, server.requestCount("bad-padding"))
			require.Zero(t, server.requestCount("not-found"))
			require.NotZero(t, server.requestCount("packet"))
		})
	}
}

// A server may hold the response of a download until the first upload of the
// session (Xray behind a CDN); a dial that waited for that response would wait
// forever (sing-box-lx SPEC 061).
func TestXHTTPDownloadHeldUntilUpload(t *testing.T) {
	for _, mode := range []string{modePacketUp, modeStreamUp} {
		t.Run(mode, func(t *testing.T) {
			options := option.V2RayXHTTPOptions{Mode: mode}
			client, _ := newTestPair(t, options, "h2", func(s *testServer) { s.holdDownload = true })
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx)
			require.NoError(t, err)
			echo(t, conn, 1024)
			conn.Close()
		})
	}
}

func TestXHTTPDownloadStatus(t *testing.T) {
	client, _ := newTestPair(t, option.V2RayXHTTPOptions{Mode: modePacketUp}, "h2", func(s *testServer) { s.downloadStatus = http.StatusNotFound })
	conn, err := client.DialContext(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Read(make([]byte, 1))
	require.ErrorContains(t, err, "404")
}

func TestXHTTPDialRefused(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := M.ParseSocksaddr(listener.Addr().String())
	listener.Close()
	transport, err := NewClient(context.Background(), N.SystemDialer, addr, option.V2RayXHTTPOptions{}, nil)
	require.NoError(t, err)
	defer transport.Close()
	start := time.Now()
	_, err = transport.DialContext(context.Background())
	require.Error(t, err)
	require.Less(t, time.Since(start), 2*time.Second)
	// The second young connection to fail in a row starts the backoff: the
	// next dial is refused at once, without connecting.
	_, err = transport.DialContext(context.Background())
	require.Error(t, err)
	_, err = transport.DialContext(context.Background())
	require.ErrorContains(t, err, "next try in")
}

// A failed upload request must release a write blocked on its body.
func TestXHTTPUploadFailureReleasesWrite(t *testing.T) {
	cases := map[string]func(*testServer){
		"status": func(s *testServer) { s.uploadStatus = http.StatusInternalServerError },
		"reset":  func(s *testServer) { s.abortUploads = true },
	}
	for name, configure := range cases {
		for _, mode := range []string{modeStreamUp, modePacketUp} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				client, _ := newTestPair(t, option.V2RayXHTTPOptions{Mode: mode}, "h2", configure)
				conn, err := client.DialContext(context.Background())
				require.NoError(t, err)
				defer conn.Close()
				done := make(chan error, 1)
				go func() {
					data := randomBytes(64 * 1024)
					for {
						if _, err := conn.Write(data); err != nil {
							done <- err
							return
						}
					}
				}()
				select {
				case err = <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("write still blocked after the upload failed")
				}
				var streamError http2.StreamError
				require.False(t, errors.As(err, &streamError), "HTTP/2 error type escaped: %T", err)
				_, err = conn.Read(make([]byte, 1))
				require.Error(t, err)
				require.False(t, errors.As(err, &streamError), "HTTP/2 error type escaped: %T", err)
			})
		}
	}
}

// Closing a session is not a failure of the server: a blocked read returns
// net.ErrClosed and the pooled connection stays in service.
func TestXHTTPCloseIsNotFailure(t *testing.T) {
	client, _ := newTestPair(t, option.V2RayXHTTPOptions{Mode: modeStreamOne}, "h2", nil)
	conn, err := client.DialContext(context.Background())
	require.NoError(t, err)
	echo(t, conn, 1024)
	readErr := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		readErr <- err
	}()
	time.Sleep(100 * time.Millisecond)
	conn.Close()
	require.ErrorIs(t, <-readErr, net.ErrClosed)
	_, err = conn.Write([]byte{1})
	require.ErrorIs(t, err, net.ErrClosed)
	time.Sleep(100 * time.Millisecond)
	client.upPool.access.Lock()
	failures, clients := client.upPool.failures, len(client.upPool.clients)
	broken := clients > 0 && client.upPool.clients[0].broken.Load()
	client.upPool.access.Unlock()
	require.Zero(t, failures)
	require.False(t, broken)
}

// Sessions share pooled connections: with the default XMUX settings at most
// three connections carry any number of sessions.
func TestXHTTPPoolReuse(t *testing.T) {
	client, _ := newTestPair(t, option.V2RayXHTTPOptions{Mode: modePacketUp}, "h2", nil)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := client.DialContext(context.Background())
			if !assertNoError(t, err) {
				return
			}
			echo(t, conn, 8*1024)
			conn.Close()
		}()
	}
	wg.Wait()
	client.upPool.access.Lock()
	clients := len(client.upPool.clients)
	client.upPool.access.Unlock()
	require.LessOrEqual(t, clients, 3)
}

func TestXHTTPRequestBudget(t *testing.T) {
	options := option.V2RayXHTTPOptions{Mode: modePacketUp}
	options.Xmux = &option.V2RayXHTTPXmuxOptions{
		MaxConnections:   &option.V2RayXHTTPRange{From: 1, To: 1},
		HMaxRequestTimes: &option.V2RayXHTTPRange{From: 4, To: 4},
	}
	client, server := newTestPair(t, options, "h2", nil)
	conn, err := client.DialContext(context.Background())
	require.NoError(t, err)
	// Many small writes, paced so that each goes in a request of its own: the
	// uploads move on to new connections as each runs out of its budget.
	for i := 0; i < 10; i++ {
		_, err = conn.Write([]byte("0123456789"))
		require.NoError(t, err)
		time.Sleep(40 * time.Millisecond)
	}
	received := make([]byte, 100)
	_, err = io.ReadFull(conn, received)
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("0123456789", 10), string(received))
	conn.Close()
	require.GreaterOrEqual(t, server.requestCount("packet"), 10)
}

// Closed sessions leave nothing behind while the pool lives on: measured
// against a warmed pool of one connection, before the client is closed.
func TestXHTTPSessionsLeaveNothing(t *testing.T) {
	for _, mode := range []string{modePacketUp, modeStreamUp, modeStreamOne} {
		t.Run(mode, func(t *testing.T) {
			options := option.V2RayXHTTPOptions{Mode: mode}
			options.Xmux = &option.V2RayXHTTPXmuxOptions{MaxConnections: &option.V2RayXHTTPRange{From: 1, To: 1}}
			client, _ := newTestPair(t, options, "h2", nil)
			warmup, err := client.DialContext(context.Background())
			require.NoError(t, err)
			echo(t, warmup, 1024)
			warmup.Close()
			time.Sleep(200 * time.Millisecond)
			baseline := runtime.NumGoroutine()
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					conn, err := client.DialContext(context.Background())
					if !assertNoError(t, err) {
						return
					}
					echo(t, conn, 32*1024)
					// Leave a read and a write in flight when closing.
					go conn.Read(make([]byte, 1))
					conn.Close()
				}()
			}
			wg.Wait()
			waitGoroutines(t, baseline)
		})
	}
}

// download sends the download half to another server (the same test server
// here, on a second listener), its own TLS and pool.
func TestXHTTPDownloadLeg(t *testing.T) {
	for _, mode := range []string{modePacketUp, modeStreamUp} {
		t.Run(mode, func(t *testing.T) {
			options := option.V2RayXHTTPOptions{Mode: mode}
			options.Path = "/x"
			serverConfig, err := newRequestConfig(options.V2RayXHTTPBaseOptions, mode)
			require.NoError(t, err)
			server := newTestServer(t, serverConfig, "h2")
			second := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				server.count("on-second")
				server.serveHTTP(w, r)
			}))
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
			defer transport.Close()
			conn, err := transport.DialContext(context.Background())
			require.NoError(t, err)
			echo(t, conn, 128*1024)
			conn.Close()
			require.Equal(t, 1, server.requestCount("on-second"), "only the download goes to the second server")
			require.Equal(t, 1, server.requestCount("download"))
		})
	}
}

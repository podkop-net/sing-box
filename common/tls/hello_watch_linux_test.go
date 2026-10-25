//go:build with_utls

package tls

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

// dropArriving adds an nftables rule that drops the packets arriving for port which match.
// They are dropped on the way in, not on the way out: a packet refused on the way out was
// never sent, as the kernel sees it, and waits in the send queue instead of going
// unacknowledged, which is not what a middlebox on the path does. The tests that need the
// rule run as root with nft at hand, in a network namespace of their own (a container).
func dropArriving(t *testing.T, port int, match string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root and nft")
	}
	table := fmt.Sprintf("hellowatch%d", port)
	script := fmt.Sprintf("add table inet %s\nadd chain inet %s input { type filter hook input priority 0; }\nadd rule inet %s input tcp dport %d %s counter drop\n", table, table, table, port, match)
	command := exec.Command("nft", "-f", "-")
	command.Stdin = strings.NewReader(script)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Skip("nft: ", err, ": ", string(output))
	}
	t.Cleanup(func() {
		exec.Command("nft", "delete", "table", "inet", table).Run()
	})
}

func listenLocal(t *testing.T, handle func(conn net.Conn)) *net.TCPAddr {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	var (
		access   sync.Mutex
		accepted []net.Conn
		running  sync.WaitGroup
	)
	// the handlers end with the test: one left behind runs into the tests after it
	t.Cleanup(func() {
		listener.Close()
		access.Lock()
		for _, conn := range accepted {
			conn.Close()
		}
		access.Unlock()
		running.Wait()
	})
	running.Add(1)
	go func() {
		defer running.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			access.Lock()
			accepted = append(accepted, conn)
			access.Unlock()
			running.Add(1)
			go func() {
				defer running.Done()
				handle(conn)
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr)
}

// A connection whose first write is never acknowledged is closed by the watch after two
// retransmissions; one whose writes arrive is left alone, and so is one nothing has been
// written to yet. The watch ends by itself when the server sends something, not when it
// acknowledges what was written: more of the ClientHello may follow.
func TestIntegrationHelloWatch(t *testing.T) {
	// the server answers one connection, when told to
	answer, done := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(done) })
	address := listenLocal(t, func(conn net.Conn) {
		go func() {
			select {
			case <-answer:
				conn.Write([]byte("answer"))
			case <-done:
			}
		}()
		io.Copy(io.Discard, conn)
		conn.Close()
	})

	delivered, err := net.Dial("tcp4", address.String())
	require.NoError(t, err)
	defer delivered.Close()
	watch := watchClientHello(delivered)
	require.NotNil(t, watch)
	time.Sleep(4 * helloWatchInterval)
	select {
	case <-watch.finished:
		t.Fatal("the watch ended before anything was written")
	default:
	}
	for range 2 {
		_, err = delivered.Write(make([]byte, 600))
		require.NoError(t, err)
		time.Sleep(4 * helloWatchInterval)
		select {
		case <-watch.finished:
			t.Fatal("the watch ended when a piece was acknowledged")
		default:
		}
	}
	answer <- struct{}{}
	select {
	case <-watch.finished:
	case <-time.After(time.Second):
		t.Fatal("the watch goes on after the server has answered")
	}
	require.False(t, watch.stop())
	_, err = delivered.Write(make([]byte, 600))
	require.NoError(t, err, "the connection stays open")

	dropArriving(t, address.Port, "meta length > 100")
	dropped, err := net.Dial("tcp4", address.String())
	require.NoError(t, err)
	defer dropped.Close()
	watch = watchClientHello(dropped)
	require.NotNil(t, watch)
	start := time.Now()
	_, err = dropped.Write(make([]byte, 600))
	require.NoError(t, err)
	select {
	case <-watch.finished:
	case <-time.After(helloWatchLimit):
		t.Fatal("the watch did not notice the unacknowledged write")
	}
	require.True(t, watch.stop())
	t.Logf("an unacknowledged write noticed after %d ms", time.Since(start).Milliseconds())
	_, err = dropped.Write([]byte("more"))
	require.Error(t, err, "the connection is closed")
}

type wrappedConn struct {
	net.Conn
}

func (c *wrappedConn) Upstream() any {
	return c.Conn
}

type wrappingDialer struct{}

func (wrappingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := N.SystemDialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return &wrappedConn{&wrappedConn{conn}}, nil
}

func (wrappingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

// otherAddrConn is a connection carried by another one: its addresses are not the socket's.
type otherAddrConn struct {
	net.Conn
}

func (c *otherAddrConn) Upstream() any {
	return c.Conn
}

func (c *otherAddrConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
}

// The watch finds the socket under the wrappers of the dialer, and leaves alone a
// connection that is not the socket to the server.
func TestHelloWatchFindsTheSocket(t *testing.T) {
	address := listenLocal(t, func(conn net.Conn) {
		io.Copy(io.Discard, conn)
		conn.Close()
	})
	conn, err := net.Dial("tcp4", address.String())
	require.NoError(t, err)
	defer conn.Close()
	require.NotNil(t, kernelTCPConn(conn))
	require.NotNil(t, kernelTCPConn(&wrappedConn{&wrappedConn{conn}}))
	require.Nil(t, kernelTCPConn(&otherAddrConn{conn}))
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	require.Nil(t, kernelTCPConn(client))
	require.Nil(t, watchClientHello(client))
	watch := watchClientHello(&wrappedConn{conn})
	require.NotNil(t, watch)
	require.False(t, watch.stop())
}

func cipherSuitesLength(t *testing.T, fingerprint string) uint16 {
	t.Helper()
	id, err := uTLSClientHelloID(fingerprint)
	require.NoError(t, err)
	uConn, err := newUClient(nil, &utls.Config{ServerName: "example.org"}, id)
	require.NoError(t, err)
	require.NoError(t, uConn.BuildHandshakeState())
	// the handshake header, the version, the random, the session ID with its length
	return binary.BigEndian.Uint16(uConn.HandshakeState.Hello.Raw[4+2+32+1+32:])
}

// A path that drops the large ClientHellos, those with the X25519MLKEM768 key share, as the
// Russian DPI does with chrome under a burst of connections: the first candidate of the
// fallback (chrome without the key share) gets through at once. Without the fallback the
// same dial waits for its handshake timeout.
func TestIntegrationFingerprintFallbackLargeHello(t *testing.T) {
	setFallback(t, true)
	quietLog(t)
	certificate := testCertificate(t)
	address := listenLocal(t, echoTLS(certificate))
	dropArriving(t, address.Port, "meta length > 1100")
	logger, warnings := newWarnLogger(t)
	options := integrationOptions("chrome")
	config, err := NewClient(context.Background(), logger, "127.0.0.1", options)
	require.NoError(t, err)
	destination := M.SocksaddrFromNet(address)
	start := time.Now()
	conn, err := NewDialer(wrappingDialer{}, config).DialTLSContext(context.Background(), destination)
	require.NoError(t, err)
	t.Logf("the dial took %d ms", time.Since(start).Milliseconds())
	echoPing(t, conn)
	conn.Close()
	require.Empty(t, warnings.take(), "no ClientHello went unanswered")
	require.Equal(t, chromeWithout, attemptName(t, newDialOf(config), "127.0.0.1"))

	setFallback(t, false)
	config, err = NewClient(context.Background(), logger, "127.0.0.1", options)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = NewDialer(N.SystemDialer, config).DialTLSContext(ctx, destination)
	require.Error(t, err)
	require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded, "the control: the ClientHello of chrome is dropped, the handshake hangs")
}

// A path that drops the ClientHello of chrome whatever its key shares: the dial gets through
// with firefox after two lost ClientHellos of the first candidate, and the dials after it
// begin with firefox.
func TestIntegrationFingerprintFallback(t *testing.T) {
	setFallback(t, true)
	quietLog(t)
	chromeSuites := cipherSuitesLength(t, "chrome")
	if chromeSuites == cipherSuitesLength(t, "firefox") {
		t.Skip("the ClientHello of chrome and firefox cannot be told apart by the length of the cipher suites")
	}
	certificate := testCertificate(t)
	address := listenLocal(t, echoTLS(certificate))
	// the length of the cipher suites follows the record header (5 bytes) and what
	// cipherSuitesLength skips, in the payload of the segment
	dropArriving(t, address.Port, fmt.Sprintf("@ih,%d,16 == %d", (5+4+2+32+1+32)*8, chromeSuites))
	logger, warnings := newWarnLogger(t)
	config, err := NewClient(context.Background(), logger, "127.0.0.1", integrationOptions("chrome"))
	require.NoError(t, err)
	// the dialer of an outbound wraps its connections, as the tracking of connections does
	dialer := NewDialer(wrappingDialer{}, config)
	destination := M.SocksaddrFromNet(address)

	start := time.Now()
	conn, err := dialer.DialTLSContext(context.Background(), destination)
	require.NoError(t, err)
	t.Logf("the first dial took %d ms", time.Since(start).Milliseconds())
	echoPing(t, conn)
	conn.Close()
	lines := warnings.take()
	require.Len(t, lines, 3)
	require.Contains(t, lines[0], "unanswered with "+chromeWithout+", trying it once more")
	require.Contains(t, lines[1], "unanswered with "+chromeWithout+", retrying with firefox")
	require.Contains(t, lines[2], "firefox is answered where "+chromeWithout+" was not")

	start = time.Now()
	conn, err = dialer.DialTLSContext(context.Background(), destination)
	require.NoError(t, err)
	t.Logf("the second dial took %d ms", time.Since(start).Milliseconds())
	echoPing(t, conn)
	conn.Close()
	// a dial that began with the ClientHello that is dropped would have said so
	require.Empty(t, warnings.take())
	require.Equal(t, "firefox", attemptName(t, newDialOf(config), "127.0.0.1"))
}

func integrationOptions(fingerprint string) option.OutboundTLSOptions {
	return option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.org",
		Insecure:   true,
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
	}
}

func echoTLS(certificate tls.Certificate) func(conn net.Conn) {
	return func(conn net.Conn) {
		defer conn.Close()
		server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}})
		if server.Handshake() != nil {
			return
		}
		io.Copy(server, server)
	}
}

func echoPing(t *testing.T, conn net.Conn) {
	_, err := conn.Write([]byte("ping"))
	require.NoError(t, err)
	answer := make([]byte, 4)
	_, err = io.ReadFull(conn, answer)
	require.NoError(t, err)
	require.Equal(t, "ping", string(answer))
}

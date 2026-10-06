package route

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type lockedBuffer struct {
	access sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.access.Lock()
	defer b.access.Unlock()
	return b.buffer.Write(p)
}

func (b *lockedBuffer) String() string {
	b.access.Lock()
	defer b.access.Unlock()
	return b.buffer.String()
}

// lines returns the log lines of level and above debug.
func (b *lockedBuffer) lines() []string {
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if line != "" && !strings.HasPrefix(line, "DEBUG") {
			lines = append(lines, line)
		}
	}
	return lines
}

// A real logger: it panics on argument types it does not format.
func newLoggedRouter(t *testing.T) (*Router, *lockedBuffer) {
	output := new(lockedBuffer)
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now(), DisableColors: true}, output, "", nil, false)
	require.NoError(t, factory.Start())
	t.Cleanup(func() { factory.Close() })
	return &Router{ctx: context.Background(), logger: factory.NewLogger("router")}, output
}

type fakeFakeIPStore struct {
	adapter.FakeIPStore
	prefix netip.Prefix
}

func (s fakeFakeIPStore) Contains(address netip.Addr) bool { return s.prefix.Contains(address) }

func (s fakeFakeIPStore) Lookup(netip.Addr) (string, bool) { return "", false }

type fakeFakeIPTransport struct {
	adapter.FakeIPTransport
	store adapter.FakeIPStore
}

func (t fakeFakeIPTransport) Store() adapter.FakeIPStore { return t.store }

type fakeDNSTransportManager struct {
	adapter.DNSTransportManager
	fakeIP adapter.FakeIPTransport
}

func (m fakeDNSTransportManager) FakeIP() adapter.FakeIPTransport { return m.fakeIP }

// closedPacketConn is the connection of a refused session: the router only closes it.
type closedPacketConn struct {
	N.PacketConn
}

func (closedPacketConn) Close() error { return nil }

func routeRefused(t *testing.T, router *Router, network string, metadata adapter.InboundContext) {
	closed := make(chan error, 1)
	onClose := func(err error) { closed <- err }
	if network == N.NetworkTCP {
		conn, peer := net.Pipe()
		defer peer.Close()
		router.RouteConnectionEx(context.Background(), conn, metadata, onClose)
	} else {
		router.RoutePacketConnectionEx(context.Background(), closedPacketConn{}, metadata, onClose)
	}
	select {
	case err := <-closed:
		require.Error(t, err, "the connection is refused")
	default:
		t.Fatal("the connection was not refused")
	}
}

// A connection to a FakeIP address the store has no record for is refused by design: the
// log says so at the warn level, with the address, not as an error of the router.
func TestMissingFakeIPRecordIsLoggedAsWarning(t *testing.T) {
	router, output := newLoggedRouter(t)
	router.dnsTransport = fakeDNSTransportManager{fakeIP: fakeFakeIPTransport{store: fakeFakeIPStore{prefix: netip.MustParsePrefix("198.18.0.0/15")}}}
	metadata := adapter.InboundContext{
		Inbound:     "tproxy-in",
		Source:      M.ParseSocksaddr("192.168.1.2:40000"),
		Destination: M.ParseSocksaddr("198.18.0.5:22"),
	}
	routeRefused(t, router, N.NetworkTCP, metadata)
	routeRefused(t, router, N.NetworkUDP, metadata)
	// the call of old inbounds returns when the connection or the router is closed
	routerContext, stopRouter := context.WithCancel(context.Background())
	stopRouter()
	router.ctx = routerContext
	require.NoError(t, router.RoutePacketConnection(context.Background(), closedPacketConn{}, metadata))

	lines := output.lines()
	require.Len(t, lines, 3, output.String())
	for _, line := range lines {
		require.True(t, strings.HasPrefix(line, "WARN"), line)
		require.Contains(t, line, "no fakeip record")
		require.Contains(t, line, "198.18.0.5:22")
	}
}

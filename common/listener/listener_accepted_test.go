package listener

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// testInbound is the handler of a listener: a connection that says "hold" stays in its handler
// until it ends, one that says "route" goes to the router (routed) and the handler returns.
type testInbound struct {
	routed chan net.Conn
	ended  chan error
}

func (i *testInbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		i.ended <- err
		conn.Close()
		return
	}
	conn.Write([]byte("ok\n"))
	if line == "route\n" {
		i.routed <- conn
		return
	}
	_, err = reader.ReadString('\n')
	i.ended <- err
	conn.Close()
}

func newTestListener(t *testing.T) (*Listener, *testInbound) {
	inbound := &testInbound{routed: make(chan net.Conn, 1), ended: make(chan error, 1)}
	listen := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	listener := New(Options{
		Context:           context.Background(),
		Logger:            log.NewNOPFactory().NewLogger("test"),
		Network:           []string{N.NetworkTCP},
		Listen:            option.ListenOptions{Listen: common.Ptr(listen)},
		ConnectionHandler: inbound,
	})
	require.NoError(t, listener.Start())
	t.Cleanup(func() { listener.Close() })
	return listener, inbound
}

func dialTestListener(t *testing.T, listener *Listener, say string) (net.Conn, *bufio.Reader) {
	conn, err := net.DialTimeout("tcp", listener.TCPListener().Addr().String(), testWait)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(testWait)))
	reader := bufio.NewReader(conn)
	if say != "" {
		_, err = conn.Write([]byte(say + "\n"))
		require.NoError(t, err)
		answer, err := reader.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "ok\n", answer)
	}
	return conn, reader
}

func held(listener *Listener) int {
	listener.accepted.access.Lock()
	defer listener.accepted.access.Unlock()
	return len(listener.accepted.conns)
}

// The connections an inbound holds end with its listener: one that waits for its handshake, one that
// waits for the next request. One that was handed over does not.
func TestCloseEndsHeldConnections(t *testing.T) {
	t.Parallel()
	for _, say := range []string{"", "hold"} {
		listener, inbound := newTestListener(t)
		_, reader := dialTestListener(t, listener, say)
		_, routedReader := dialTestListener(t, listener, "route")
		routed := <-inbound.routed
		defer routed.Close()
		require.Eventually(t, func() bool { return held(listener) == 1 }, testWait, 5*time.Millisecond, "the connection handed over is not held")
		require.NoError(t, listener.Close())
		_, err := reader.ReadByte()
		require.Error(t, err)
		require.False(t, E.IsTimeout(err), "the held connection was left open: %v", err)
		require.Error(t, <-inbound.ended)
		// the router has the other one
		_, err = routed.Write([]byte("from the router\n"))
		require.NoError(t, err)
		answer, err := routedReader.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "from the router\n", answer)
		require.Zero(t, held(listener))
	}
}

// A connection that ended by itself is not kept, and one accepted while the listener closes is
// closed.
func TestHeldConnectionsForgotten(t *testing.T) {
	t.Parallel()
	listener, inbound := newTestListener(t)
	conn, _ := dialTestListener(t, listener, "hold")
	require.Equal(t, 1, held(listener))
	conn.Close()
	require.Error(t, <-inbound.ended)
	require.Eventually(t, func() bool { return held(listener) == 0 }, testWait, 5*time.Millisecond)
	require.NoError(t, listener.Close())

	client, server := net.Pipe()
	defer client.Close()
	listener.handleTCP(context.Background(), server, adapter.InboundContext{InboundType: C.TypeMixed})
	_, err := client.Read(make([]byte, 1))
	require.Error(t, err)
	require.Empty(t, inbound.ended, "a closed inbound serves nothing")
}

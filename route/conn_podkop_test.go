package route

import (
	"context"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

type levelLogger struct {
	logger.ContextLogger
	debug, errors int
}

func (l *levelLogger) DebugContext(context.Context, ...any) { l.debug++ }
func (l *levelLogger) ErrorContext(context.Context, ...any) { l.errors++ }

type typedOutbound struct {
	outbound.Adapter
}

func (o *typedOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, os.ErrInvalid
}

func (o *typedOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

// A connection a block outbound refused is logged at debug, as one the reject action refused;
// another that could not be opened stays an error.
func TestLogDialError(t *testing.T) {
	logged := &levelLogger{}
	manager := &ConnectionManager{logger: logged}
	manager.logDialError(context.Background(), &typedOutbound{Adapter: outbound.NewAdapter(C.TypeBlock, "block-out", nil, nil)}, os.ErrPermission)
	require.Equal(t, 1, logged.debug)
	require.Zero(t, logged.errors)
	manager.logDialError(context.Background(), &typedOutbound{Adapter: outbound.NewAdapter(C.TypeVLESS, "server", nil, nil)}, os.ErrDeadlineExceeded)
	require.Equal(t, 1, logged.errors)
}

// The copies of both directions feed what the block detector reads, through the counters they take
// out of the tracker. A cut is a connection closed on this side, never told the server ended the
// stream, whose client was waiting for the server; the other two are not. The wait is real: the
// copies take the counters as they are, and the test goes through them.
func TestConnectionCopyDetectFlows(t *testing.T) {
	const size = 16 << 10
	flows := func(t *testing.T, waits bool, serverCloses bool) trafficcontrol.DetectFlowSample {
		manager := trafficcontrol.NewManager()
		connections := NewConnectionManager(context.Background(), logger.NOP())
		member := &typedOutbound{outbound.NewAdapter(C.TypeVLESS, "s", nil, nil)}
		client, lan := net.Pipe()
		defer lan.Close()
		go io.Copy(io.Discard, lan)
		tracked := manager.RoutedConnection(context.Background(), client, adapter.InboundContext{OutboundChain: []adapter.Outbound{member}}, nil, member)
		remote, server := net.Pipe()
		defer server.Close()
		var done atomic.Bool
		downloaded := make(chan struct{})
		go func() {
			defer close(downloaded)
			connections.connectionCopy(context.Background(), remote, tracked, true, &done, nil)
		}()
		uploaded := make(chan struct{})
		go func() {
			defer close(uploaded)
			connections.connectionCopy(context.Background(), tracked, remote, false, &done, nil)
		}()
		go io.Copy(io.Discard, server)
		_, err := server.Write(make([]byte, size))
		require.NoError(t, err)
		open := manager.Connections()
		require.Len(t, open, 1)
		require.True(t, open[0].PendingSince().IsZero())
		if waits {
			time.Sleep(5*time.Second + 500*time.Millisecond)
			_, err = lan.Write([]byte{1})
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				return !open[0].PendingSince().IsZero()
			}, time.Second, 5*time.Millisecond, "the client wrote after a quiet time")
			time.Sleep(3*time.Second + 200*time.Millisecond)
		}
		if serverCloses {
			require.NoError(t, server.Close())
		} else {
			require.NoError(t, remote.Close())
		}
		<-downloaded
		<-uploaded
		require.NoError(t, tracked.Close())
		return manager.DetectFlows()["s"]
	}
	t.Run("healthy flow closed on this side", func(t *testing.T) {
		t.Parallel()
		sample := flows(t, false, false)
		require.Empty(t, sample.Cuts)
		require.False(t, sample.LastDataAt.IsZero())
	})
	t.Run("the server ended a flow that waited", func(t *testing.T) {
		t.Parallel()
		sample := flows(t, true, true)
		require.Empty(t, sample.Cuts)
		require.False(t, sample.LastDataAt.IsZero())
	})
	t.Run("cut", func(t *testing.T) {
		t.Parallel()
		sample := flows(t, true, false)
		require.Len(t, sample.Cuts, 1)
		require.Equal(t, int64(size), sample.Cuts[0].Download)
		require.Equal(t, int64(1), sample.Cuts[0].Upload)
		// the wait began after the flow opened, and stood for its 3 s before the close
		require.True(t, sample.Cuts[0].PendingSince.After(sample.Cuts[0].CreatedAt))
		require.GreaterOrEqual(t, sample.Cuts[0].ClosedAt.Sub(sample.Cuts[0].PendingSince), 3*time.Second)
	})
}

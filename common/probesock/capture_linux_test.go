//go:build linux

package probesock

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/sagernet/sing/common/control"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func serve(t *testing.T, size int) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// the client speaks first, as through a proxy: nothing comes before the
				// capture is on
				request := make([]byte, 1)
				if _, err := io.ReadFull(conn, request); err != nil {
					return
				}
				conn.Write(make([]byte, size))
			}()
		}
	}()
	return listener.Addr().String()
}

func skipWithoutCapture(t *testing.T, err error) {
	if err != nil && strings.Contains(err.Error(), "operation not permitted") {
		t.Skip("no CAP_NET_RAW: ", err)
	}
}

// The probe connection of a context: a small receive buffer, and every byte of it counted
// once over the loopback (seen there both as sent and as received), nothing lost.
func TestCaptureLoopback(t *testing.T) {
	const size = 1 << 20
	address := serve(t, size)
	ctx, socket := With(context.Background(), Window)
	conn, err := socket.Dial(ctx, net.Dialer{}, "tcp", address)
	require.NoError(t, err)
	defer conn.Close()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	require.NoError(t, err)
	clamp := func() int {
		var value int
		require.NoError(t, control.Raw(raw, func(fd uintptr) error {
			var err error
			value, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP)
			return err
		}))
		return value
	}
	// the window of the probe is clamped once the connection is established
	require.Equal(t, Window, clamp())
	_, err = conn.Write([]byte{1})
	require.NoError(t, err)
	received, err := io.Copy(io.Discard, conn)
	require.NoError(t, err)
	require.Equal(t, int64(size), received)
	result, err := socket.Finish()
	skipWithoutCapture(t, err)
	require.NoError(t, err)
	require.Zero(t, result.Dropped)
	require.Equal(t, int64(size), result.Bytes)
	// the probe done, the connection may carry other traffic: its window may grow again, its
	// buffer no larger than the kernel's tuning would make it
	require.Equal(t, systemBufferMax(), clamp())
	require.NoError(t, control.Raw(raw, func(fd uintptr) error {
		buffer, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		if err == nil && buffer > systemBufferMax() {
			t.Errorf("the buffer is %d, the tuning stops at %d", buffer, systemBufferMax())
		}
		return err
	}))
	require.Zero(t, result.Lost)
	require.Zero(t, result.DupBytes)
	require.Positive(t, result.Segments)
	require.Positive(t, result.RTT)
}

// Only the first dial under the context is the probe connection.
func TestSecondDialOrdinary(t *testing.T) {
	address := serve(t, 64<<10)
	ctx, socket := With(context.Background(), Window)
	first, err := socket.Dial(ctx, net.Dialer{}, "tcp", address)
	require.NoError(t, err)
	defer first.Close()
	second, err := socket.Dial(ctx, net.Dialer{}, "tcp", address)
	require.NoError(t, err)
	defer second.Close()
	_, err = first.Write([]byte{1})
	require.NoError(t, err)
	_, err = second.Write([]byte{1})
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, second)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, first)
	require.NoError(t, err)
	result, err := socket.Finish()
	skipWithoutCapture(t, err)
	require.NoError(t, err)
	require.Equal(t, int64(64<<10), result.Bytes)
	require.Nil(t, From(Without(ctx)))
}

// Without a dial there is nothing to count.
func TestFinishWithoutDial(t *testing.T) {
	_, socket := With(context.Background(), Window)
	_, err := socket.Finish()
	require.Error(t, err)
	socket.Close()
}

// A dial under the context of a probe that is over is an ordinary connection: no capture is
// started that nobody would stop.
func TestSealedAfterClose(t *testing.T) {
	address := serve(t, 64<<10)
	ctx, socket := With(context.Background(), Window)
	socket.Close()
	conn, err := socket.Dial(ctx, net.Dialer{}, "tcp", address)
	require.NoError(t, err)
	defer conn.Close()
	socket.access.Lock()
	require.Nil(t, socket.capture)
	require.Nil(t, socket.conn)
	socket.access.Unlock()
	_, err = socket.Finish()
	require.ErrorIs(t, err, ErrNoOwnConnection)
}

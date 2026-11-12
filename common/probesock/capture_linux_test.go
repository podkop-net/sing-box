//go:build linux

package probesock

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// flood sends TCP segments with the addresses of a connection, as its far end would, from raw
// sockets (workers at once), until the returned function is called: each of a byte of data, with
// the sequence number sequence gives for its count. Their checksums are wrong: the kernel's TCP
// drops them, the capture, which sees every packet before that, takes them.
func flood(t *testing.T, local net.Addr, remote net.Addr, workers int, sequence func(count uint32) uint32) (stop func() int64) {
	t.Helper()
	localPort, remotePort := netip.MustParseAddrPort(local.String()), netip.MustParseAddrPort(remote.String())
	var (
		sent    atomic.Int64
		count   atomic.Uint32
		stopped atomic.Bool
		group   sync.WaitGroup
	)
	for worker := 0; worker < workers; worker++ {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
		if err != nil {
			t.Skip("no raw socket: ", err)
		}
		group.Add(1)
		go func() {
			defer group.Done()
			defer unix.Close(fd)
			packet := make([]byte, 41)
			packet[0], packet[8], packet[9] = 0x45, 64, unix.IPPROTO_TCP
			binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
			source, destination := remotePort.Addr().As4(), localPort.Addr().As4()
			copy(packet[12:], source[:])
			copy(packet[16:], destination[:])
			binary.BigEndian.PutUint16(packet[20:], remotePort.Port())
			binary.BigEndian.PutUint16(packet[22:], localPort.Port())
			packet[32], packet[33] = 5<<4, 0x10
			to := &unix.SockaddrInet4{Addr: destination}
			for !stopped.Load() {
				binary.BigEndian.PutUint32(packet[24:], sequence(count.Add(1)))
				if unix.Sendto(fd, packet, 0, to) == nil {
					sent.Add(1)
				}
			}
		}()
	}
	return func() int64 {
		stopped.Store(true)
		group.Wait()
		return sent.Load()
	}
}

// probed opens a probe connection, downloads size bytes over it and returns the socket with the
// capture still on, and the sequence number of the first byte the capture counted.
func probed(t *testing.T, size int) (*Socket, net.Conn, uint32) {
	t.Helper()
	address := serve(t, size)
	ctx, socket := With(context.Background(), Window)
	conn, err := socket.Dial(ctx, net.Dialer{}, "tcp", address)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	socket.access.Lock()
	capture, captureErr := socket.capture, socket.err
	socket.access.Unlock()
	skipWithoutCapture(t, captureErr)
	require.NoError(t, captureErr)
	_, err = conn.Write([]byte{1})
	require.NoError(t, err)
	received, err := io.Copy(io.Discard, conn)
	require.NoError(t, err)
	require.Equal(t, int64(size), received)
	var base uint32
	require.Eventually(t, func() bool {
		capture.access.Lock()
		defer capture.access.Unlock()
		base = capture.counter.base
		return capture.counter.highest >= int64(size)
	}, 5*time.Second, time.Millisecond)
	return socket, conn, base
}

// finishWithin ends the probe and fails the test when that takes longer than limit.
func finishWithin(t *testing.T, socket *Socket, limit time.Duration) (Result, time.Duration) {
	t.Helper()
	type finished struct {
		result Result
		err    error
	}
	done := make(chan finished, 1)
	start := time.Now()
	go func() {
		result, err := socket.Finish()
		done <- finished{result, err}
	}()
	select {
	case end := <-done:
		require.NoError(t, end.err)
		return end.result, time.Since(start)
	case <-time.After(limit):
		t.Fatalf("the probe did not end within %v: the capture goes on reading", limit)
		return Result{}, 0
	}
}

// A far end that never stops sending (packets of data the connection has already, as fast as
// four senders make them) does not keep the probe: the capture ends at the first packet that
// came after the stop.
func TestCaptureStopUnderFlood(t *testing.T) {
	socket, _, base := probed(t, 64<<10)
	stop := flood(t, socket.conn.LocalAddr(), socket.conn.RemoteAddr(), 4, func(uint32) uint32 { return base })
	time.Sleep(time.Second)
	socket.access.Lock()
	capture := socket.capture
	socket.access.Unlock()
	capture.access.Lock()
	before := capture.counter.Packets
	capture.access.Unlock()
	time.Sleep(time.Second)
	capture.access.Lock()
	rate := capture.counter.Packets - before
	capture.access.Unlock()
	result, took := finishWithin(t, socket, drainLimit+2*time.Second)
	sent := stop()
	t.Logf("the flood: %d packets sent, the capture read %d a second, dropped %d; the stop took %v", sent, rate, result.Dropped, took)
	require.False(t, result.Broken)
	require.Less(t, took, drainLimit+500*time.Millisecond)
	require.Equal(t, int64(64<<10), result.Bytes)
}

// A far end that sends holes without end (every packet three bytes past the one before) is told
// as no stream of a probe: the capture stops reading at maxHoles holes, keeps none of them, and
// the probe ends at once.
func TestCaptureHolesWithoutEnd(t *testing.T) {
	socket, _, base := probed(t, 64<<10)
	stop := flood(t, socket.conn.LocalAddr(), socket.conn.RemoteAddr(), 1, func(count uint32) uint32 { return base + 1<<20 + 3*count })
	socket.access.Lock()
	capture := socket.capture
	socket.access.Unlock()
	select {
	case <-capture.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the capture goes on reading holes without end")
	}
	capture.access.Lock()
	require.True(t, capture.counter.Broken)
	require.Nil(t, capture.counter.holes)
	capture.access.Unlock()
	result, took := finishWithin(t, socket, 2*time.Second)
	sent := stop()
	t.Logf("the flood: %d packets sent; the stop took %v", sent, took)
	require.True(t, result.Broken)
}

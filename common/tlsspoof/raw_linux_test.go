package tlsspoof

import (
	"context"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing/common/control"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func dialLocalWith(t *testing.T, dialControl func(fd int)) (*net.TCPConn, chan []byte) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		data, _ := io.ReadAll(conn)
		received <- data
	}()
	dialer := net.Dialer{Control: func(network, address string, conn syscall.RawConn) error {
		return conn.Control(func(fd uintptr) {
			if dialControl != nil {
				dialControl(int(fd))
			}
		})
	}}
	client, err := dialer.DialContext(context.Background(), "tcp4", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() {
		client.Close()
		listener.Close()
	})
	return client.(*net.TCPConn), received
}

// The raw socket takes the mark, the device and the local address of the connection: the
// kernel routes by them, and without them the forged ClientHello may leave another way.
func TestIntegrationSpooferFollowsConnection(t *testing.T) {
	requireRoot(t)
	client, _ := dialLocalWith(t, func(fd int) {
		require.NoError(t, unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, 0x29a))
		require.NoError(t, unix.BindToDevice(fd, loopbackInterface))
	})
	created, err := newRawSpoofer(client, MethodWrongSequence)
	require.NoError(t, err)
	spoofer := created.(*linuxSpoofer)
	require.NoError(t, spoofer.open())
	defer spoofer.Close()

	mark, err := unix.GetsockoptInt(spoofer.rawFD, unix.SOL_SOCKET, unix.SO_MARK)
	require.NoError(t, err)
	require.Equal(t, 0x29a, mark)
	device, err := unix.GetsockoptString(spoofer.rawFD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	require.NoError(t, err)
	require.Equal(t, loopbackInterface, device)
	local, err := unix.Getsockname(spoofer.rawFD)
	require.NoError(t, err)
	require.Equal(t, client.LocalAddr().(*net.TCPAddr).IP.To4(), net.IP(local.(*unix.SockaddrInet4).Addr[:]))
}

func segmentsSent(t *testing.T, conn *net.TCPConn) uint32 {
	t.Helper()
	var sent uint32
	require.NoError(t, control.Conn(conn, func(fd uintptr) error {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err != nil {
			return err
		}
		sent = info.Segs_out
		return nil
	}))
	return sent
}

// Reading the sequence numbers sends nothing on the connection. Leaving the repair mode
// the plain way sends a window probe, which the control shows on the same kernel.
func TestIntegrationSpooferSendsNoWindowProbe(t *testing.T) {
	requireRoot(t)
	client, _ := dialLocalWith(t, nil)
	before := segmentsSent(t, client)
	created, err := newRawSpoofer(client, MethodWrongSequence)
	require.NoError(t, err)
	spoofer := created.(*linuxSpoofer)
	require.NoError(t, spoofer.open())
	require.NoError(t, spoofer.Close())
	require.Equal(t, before, segmentsSent(t, client), "segments sent by the connection while the spoofer read its state")

	control1, _ := dialLocalWith(t, nil)
	before = segmentsSent(t, control1)
	require.NoError(t, control.Conn(control1, func(fd uintptr) error {
		err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON)
		if err != nil {
			return err
		}
		return unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_OFF)
	}))
	require.Equal(t, before+1, segmentsSent(t, control1), "the control: the plain way out of the repair mode sends a window probe")
}

func openDescriptors(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	return len(entries)
}

// A connection wrapped and never written to holds no raw socket, and one that has sent its
// forged ClientHello has closed it: closing the underlying connection alone, as a failed
// handshake does, leaves nothing open.
func TestIntegrationSpooferHoldsNoSocket(t *testing.T) {
	requireRoot(t)
	client, received := dialLocalWith(t, nil)
	before := openDescriptors(t)
	for range 20 {
		_, err := NewConn(client, MethodWrongSequence, "letsencrypt.org")
		require.NoError(t, err)
	}
	require.Equal(t, before, openDescriptors(t), "descriptors after wrapping without a write")
	wrapped, err := NewConn(client, MethodWrongSequence, "letsencrypt.org")
	require.NoError(t, err)
	_, err = wrapped.Write([]byte("real"))
	require.NoError(t, err)
	require.Equal(t, before, openDescriptors(t), "descriptors after the forged ClientHello was sent")
	require.NoError(t, client.Close())
	require.Equal(t, []byte("real"), <-received)
}

// wrong-timestamp is refused on a connection without TCP timestamps: the peer would take
// the forged ClientHello for data. Runs where net.ipv4.tcp_timestamps is 0.
func TestIntegrationWrongTimestampNeedsTimestamps(t *testing.T) {
	requireRoot(t)
	if !tcpTimestampsOff() {
		t.Skip("net.ipv4.tcp_timestamps is not 0")
	}
	client, received := dialLocalWith(t, nil)
	wrapped, err := NewConn(client, MethodWrongTimestamp, "letsencrypt.org")
	require.NoError(t, err)
	_, err = wrapped.Write([]byte("real"))
	require.ErrorContains(t, err, "wrong-timestamp needs TCP timestamps")
	require.NoError(t, client.Close())
	require.Empty(t, <-received, "nothing reaches the peer: neither the forged ClientHello nor the write that was refused")

	other, received := dialLocalWith(t, nil)
	wrapped, err = NewConn(other, MethodWrongSequence, "letsencrypt.org")
	require.NoError(t, err)
	_, err = wrapped.Write([]byte("real"))
	require.NoError(t, err)
	require.NoError(t, other.Close())
	require.Equal(t, []byte("real"), <-received)
}

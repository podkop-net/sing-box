package tf

import (
	"context"
	"net"
	"time"

	"github.com/sagernet/sing/common/control"

	"golang.org/x/sys/unix"
)

func writeAndWaitAck(ctx context.Context, conn *net.TCPConn, payload []byte, fallbackDelay time.Duration) error {
	_, err := conn.Write(payload)
	if err != nil {
		return err
	}
	// The socket is looked at for a moment at a time (podkop-engine). The wait used to be
	// made inside one visit to it, and a Close waits for such a visit to end: when the
	// piece was never acknowledged, nothing could end the write short of the kernel
	// giving the connection up, not the handshake timeout either, which closes the
	// connection. A closed connection now ends the wait at its next look.
	start := time.Now()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		var unacked uint32
		err = control.Conn(conn, func(fd uintptr) error {
			tcpInfo, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
			if err != nil {
				return err
			}
			unacked = tcpInfo.Unacked
			return nil
		})
		if err != nil {
			return err
		}
		if unacked == 0 {
			if time.Since(start) <= 20*time.Millisecond {
				// under transparent proxy
				time.Sleep(fallbackDelay)
			}
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
}

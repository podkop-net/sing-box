package tls

import (
	"net"
	"syscall"
	"time"

	"github.com/sagernet/sing/common"

	"golang.org/x/sys/unix"
)

var (
	helloWatchInterval = 50 * time.Millisecond
	// retransmissions by timeout in a row, as the kernel counts them, after which the
	// ClientHello is taken for dropped: on a path of 50 ms that is about a second
	helloWatchRetransmits uint8 = 2
	// what is written stays unacknowledged this long: the same, however the kernel
	// paces its retransmissions
	helloWatchLimit = 5 * time.Second
)

// watchClientHello closes conn when what the client writes to it stays unacknowledged
// through helloWatchRetransmits retransmissions (or for helloWatchLimit) while nothing
// has come from the server. The watch ends by itself once the server has acknowledged
// all that was written or has sent anything: from then on a stalled connection is not
// the ClientHello's doing. A connection that is not a TCP socket of the kernel is not
// watched.
func watchClientHello(conn net.Conn) *helloWatch {
	tcpConn := kernelTCPConn(conn)
	if tcpConn == nil {
		return nil
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return nil
	}
	watch := &helloWatch{
		stopped:  make(chan struct{}),
		finished: make(chan struct{}),
	}
	go watch.run(tcpConn, rawConn)
	return watch
}

// kernelTCPConn finds the TCP socket a connection of the dialer is: the dialer wraps what
// it returns (the tracking of connections, counters). A connection carried by another
// one, as with a detour, is not a socket to the server: it has addresses of its own, or
// is past its first flight, which the watch then sees at once.
func kernelTCPConn(conn net.Conn) *net.TCPConn {
	tcpConn, isTCP := common.Cast[*net.TCPConn](conn)
	if !isTCP || tcpConn == nil {
		return nil
	}
	if conn.RemoteAddr() == nil || tcpConn.RemoteAddr() == nil || conn.LocalAddr() == nil || tcpConn.LocalAddr() == nil ||
		conn.RemoteAddr().String() != tcpConn.RemoteAddr().String() || conn.LocalAddr().String() != tcpConn.LocalAddr().String() {
		return nil
	}
	return tcpConn
}

func (w *helloWatch) run(tcpConn *net.TCPConn, rawConn syscall.RawConn) {
	defer close(w.finished)
	ticker := time.NewTicker(helloWatchInterval)
	defer ticker.Stop()
	var unackedSince time.Time
	for {
		select {
		case <-w.stopped:
			return
		case <-ticker.C:
		}
		var (
			info    *unix.TCPInfo
			infoErr error
		)
		err := rawConn.Control(func(fd uintptr) {
			info, infoErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		})
		if err != nil || infoErr != nil {
			return
		}
		switch {
		case info.Bytes_received > 0:
			return
		case info.Unacked == 0:
			// more than the SYN acknowledged: the ClientHello has arrived
			if info.Bytes_acked > 1 {
				return
			}
			unackedSince = time.Time{}
		default:
			if unackedSince.IsZero() {
				unackedSince = time.Now()
			}
			if info.Retransmits >= helloWatchRetransmits || time.Since(unackedSince) >= helloWatchLimit {
				w.unanswered.Store(true)
				tcpConn.Close()
				return
			}
		}
	}
}

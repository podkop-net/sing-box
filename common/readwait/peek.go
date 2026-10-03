// Package readwait lets connections that can wait for data without consuming it wait
// without a buffer (podkop-engine).
//
// The copy loop of sing takes a pool buffer before every blocking read of a source that has
// no read waiter, so an idle proxied connection held a 32 KiB buffer (64 KiB after 512 KB)
// for as long as its server stayed silent. A connection that can wait for data without
// consuming it (a quic-go stream, a bufio reader) gets a read waiter here: it waits first,
// then takes the buffer and reads through the connection's own Read, so the framing and the
// errors stay the connection's.
package readwait

import (
	"io"
	"net"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

type PeekWaiter struct {
	reader  io.Reader
	wait    func() error
	options N.ReadWaitOptions
	pending error
}

// NewPeekWaiter returns a read waiter that calls wait until data can be read, then reads
// from reader. wait must not consume anything; its error is left to the read, which
// reports it the way the connection does.
func NewPeekWaiter(reader io.Reader, wait func() error) *PeekWaiter {
	return &PeekWaiter{reader: reader, wait: wait}
}

func (w *PeekWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	w.options = options
	return false
}

func (w *PeekWaiter) WaitReadBuffer() (*buf.Buffer, error) {
	if w.pending != nil {
		err := w.pending
		w.pending = nil
		return nil, err
	}
	for {
		waitErr := w.wait()
		buffer := w.options.NewBuffer()
		n, err := w.reader.Read(buffer.FreeBytes())
		if n > 0 {
			buffer.Truncate(n)
			w.options.PostReturn(buffer)
			w.pending = err // delivered with the next call, as io.Reader allows
			return buffer, nil
		}
		buffer.Release()
		if err != nil {
			return nil, err
		}
		if waitErr != nil {
			return nil, waitErr
		}
		// an empty read (an empty frame): wait again without holding the buffer
	}
}

type quicStream interface {
	Peek(b []byte) (int, error)
}

// QUICStreamConn is a connection over a quic-go stream: Peek blocks until data arrives
// (or the stream ends, fails, or reaches its read deadline) and consumes nothing.
type QUICStreamConn struct {
	net.Conn
	stream     quicStream
	peekBuffer [1]byte
}

// NewQUICStreamConn gives conn a read waiter when it is a quic-go stream with Peek, as the
// TCP connections of Hysteria2 and TUIC are; other connections are returned as they are.
func NewQUICStreamConn(conn net.Conn) net.Conn {
	stream, isStream := conn.(quicStream)
	if !isStream {
		return conn
	}
	return &QUICStreamConn{Conn: conn, stream: stream}
}

func (c *QUICStreamConn) CreateReadWaiter() (N.ReadWaiter, bool) {
	return NewPeekWaiter(c.Conn, func() error {
		_, err := c.stream.Peek(c.peekBuffer[:])
		return err
	}), true
}

func (c *QUICStreamConn) Upstream() any {
	return c.Conn
}

func (c *QUICStreamConn) WriterReplaceable() bool {
	return true
}

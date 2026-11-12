package v2rayquic

import (
	"net"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/common/readwait"
	qtls "github.com/sagernet/sing-quic"
	N "github.com/sagernet/sing/common/network"
)

type StreamWrapper struct {
	Conn *quic.Conn
	*quic.Stream
	closeOnce sync.Once
	onClose   func()
}

func (s *StreamWrapper) Read(p []byte) (n int, err error) {
	n, err = s.Stream.Read(p)
	return n, qtls.WrapError(err)
}

// CreateReadWaiter lets the copy loop wait for data with Peek before it takes a buffer
// (podkop-engine, see common/readwait).
func (s *StreamWrapper) CreateReadWaiter() (N.ReadWaiter, bool) {
	peekBuffer := make([]byte, 1)
	return readwait.NewPeekWaiter(s, func() error {
		_, err := s.Stream.Peek(peekBuffer)
		return err
	}), true
}

func (s *StreamWrapper) Write(p []byte) (n int, err error) {
	n, err = s.Stream.Write(p)
	return n, qtls.WrapError(err)
}

func (s *StreamWrapper) LocalAddr() net.Addr {
	return s.Conn.LocalAddr()
}

func (s *StreamWrapper) RemoteAddr() net.Addr {
	return s.Conn.RemoteAddr()
}

func (s *StreamWrapper) Upstream() any {
	return s.Stream
}

func (s *StreamWrapper) Close() error {
	s.CancelRead(0)
	s.Stream.Close()
	// quic-go's Stream.Close does not unblock a Write blocked on flow control,
	// but a past write deadline does; buffered data and the FIN are unaffected.
	s.Stream.SetWriteDeadline(time.Now())
	if s.onClose != nil {
		s.closeOnce.Do(s.onClose)
	}
	return nil
}

package probesock

import (
	"context"
	"net"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// Window is the most a probe connection offers its server, about a dozen segments. On the
// stand a 1 MB download with a window of 16-24 KB lost nothing on a 25-packet queue and on a
// 10 Mbit/s line, where a download with the ordinary window lost 6-13 %, and still showed a
// random loss of 1 % as 0.8-1.25 %.
const Window = 20 << 10

type contextKey struct{}

// Socket is the probe connection of a context: the first TCP connection a dialer opens
// under it (see Dial). One probe, one socket: a context is made for each probe.
type Socket struct {
	window int

	access   sync.Mutex
	taken    bool
	conn     *net.TCPConn
	connect  time.Duration
	capture  *capture
	err      error
	restored bool
	// sealed: the probe is over (Finish or Close). A transport may still dial under its context
	// afterwards (in the background, with the cancellation taken off): that is an ordinary
	// connection, with no capture nobody would stop
	sealed bool
}

// ErrNoOwnConnection tells that the probe went over no TCP connection of its own: a
// multiplexed transport took a connection it had, or the transport is not TCP. Probing the
// member again would not count either.
var ErrNoOwnConnection = E.New("no connection of its own")

// restore lets the window of the probe connection grow again once the probe has run: a
// multiplexed transport (gRPC, HTTP/2, xhttp, mux) keeps the connection a probe dialed in its
// pool and carries other connections over it, which a window of 20 KB would hold to a crawl
// (on the stand, a gRPC server 25 ms away: 7 Mbit/s). Called under access.
func (s *Socket) restore() {
	if s.conn == nil || s.restored {
		return
	}
	s.restored = true
	restoreWindow(s.conn)
}

// With returns a context under which the first TCP dial is a probe connection with a
// receive buffer of window bytes.
func With(ctx context.Context, window int) (context.Context, *Socket) {
	socket := &Socket{window: window}
	return context.WithValue(ctx, contextKey{}, socket), socket
}

// From returns the probe socket of the context, nil when it has none.
func From(ctx context.Context) *Socket {
	socket, _ := ctx.Value(contextKey{}).(*Socket)
	return socket
}

// Without returns a context whose dials are no probe connection: for the dials a probe
// causes on the side, as the queries that resolve the server's name.
func Without(ctx context.Context) context.Context {
	if From(ctx) == nil {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, (*Socket)(nil))
}

// take reports whether this dial is the probe connection: the first one under the context.
func (s *Socket) take() bool {
	if s == nil {
		return false
	}
	s.access.Lock()
	defer s.access.Unlock()
	if s.taken || s.sealed {
		return false
	}
	s.taken = true
	return true
}

// Dial dials address with dialer. The first dial under the context that connects is the
// probe connection: once it is established its window is clamped to the window of the probe
// (the kernel's first window is ten segments, below it) and its packets are captured, before
// any data moves (the client speaks first through a proxy). Every later dial is an ordinary
// one.
func (s *Socket) Dial(ctx context.Context, dialer net.Dialer, network string, address string) (net.Conn, error) {
	if !s.take() {
		return dialer.DialContext(ctx, network, address)
	}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		// the next address of the server, dialed after this one, is the probe connection
		s.access.Lock()
		s.taken = false
		s.access.Unlock()
		return nil, err
	}
	connect := time.Since(start)
	s.access.Lock()
	defer s.access.Unlock()
	if s.sealed {
		// the probe ended while this dialed: an ordinary connection
		return conn, nil
	}
	s.connect = connect
	tcpConn, isTCP := conn.(*net.TCPConn)
	if !isTCP {
		s.err = E.Cause(ErrNoOwnConnection, "not a TCP connection")
		return conn, nil
	}
	s.conn = tcpConn
	if s.err = clampWindow(tcpConn, s.window); s.err != nil {
		// a probe whose window is not held could make its own loss: not counted
		return conn, nil
	}
	s.capture, s.err = startCapture(tcpConn)
	return conn, nil
}

// Result is what a probe connection showed.
type Result struct {
	Counts
	Segments int           // segments of data that came
	Lost     int           // of them lost on the way
	RTT      time.Duration // the least RTT of the connection, or its connect time
	MSS      int
	Dropped  int // packets the capture could not keep: the counts are short
}

// Finish ends the capture and returns the counts, before the connection is closed (its
// TCP information is read). An error tells that the probe had no connection of its own to
// count: the dial went over a connection opened before (a multiplexed transport), over UDP,
// or the capture could not run.
func (s *Socket) Finish() (Result, error) {
	s.access.Lock()
	defer s.access.Unlock()
	s.sealed = true
	var result Result
	if !s.taken || s.conn == nil {
		if s.err != nil {
			return result, s.err
		}
		return result, ErrNoOwnConnection
	}
	if s.capture == nil {
		s.restore()
		return result, E.Cause(s.err, "capture")
	}
	result.RTT = s.connect
	if info, err := tcpInfo(s.conn); err == nil {
		result.MSS = info.mss
		if info.minRTT > 0 {
			result.RTT = info.minRTT
		}
	}
	counter, dropped := s.capture.stop()
	s.capture = nil
	s.restore()
	result.Counts = counter.finish(reorderWindow(result.RTT))
	result.Dropped = dropped
	result.Segments, result.Lost = result.Counts.segments(result.MSS)
	return result, nil
}

// Close ends a capture that Finish did not end: the probe failed on the way.
func (s *Socket) Close() {
	if s == nil {
		return
	}
	s.access.Lock()
	defer s.access.Unlock()
	s.sealed = true
	if s.capture != nil {
		s.capture.stop()
		s.capture = nil
	}
	s.restore()
}

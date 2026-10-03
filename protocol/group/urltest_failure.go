package group

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

// What the group learns from the traffic of its members (podkop-engine).
//
// Upstream urltest learns that a member is broken only from its periodic URL test, so a
// dead server keeps failing every new connection for up to an interval. Here a failed dial
// through the selected member, or a failed write that carried the handshake the dial
// deferred, is evidence about the member, used without constants of its own:
//
//   - A TCP dial of a protocol that contacts only its own server before the first payload
//     (see serverOnlyDial) fails for one reason: the server or the way to it. The URL test
//     dials the same way and would fail the same way, so the failure counts as that test:
//     the single failed test that already marks a member unavailable. The group selects
//     again at once; TCP and TLS have already retried until their own timeouts.
//   - Members that reach the destination when they dial (socks and http CONNECT, direct,
//     groups) may fail because of the destination, and a packet listen may fail for a
//     reason the URL test, made over TCP, would not see. One URL test of the member, the
//     periodic one run out of turn, decides (confirmFailure).
//
// A failed dial is not judged at all when another dial through the same member succeeded
// after it began: the member was reachable meanwhile, the failure was the connection's
// own (a lost SYN on a lossy link, a destination the proxy could not reach). On a busy
// router this refutes nearly every chance failure, and a dead member has no successes to
// refute with. A failed handshake write is not refuted this way: when the server, or the
// path, drops the first data, every dial succeeds. Only a member with a test result is
// judged, the others are unavailable already, and a failure the caller caused (it
// canceled, or closed the connection itself) says nothing.

// serverOnlyDial reports whether a dial through outbound contacts only its server, so that a
// failed dial or handshake write is the server's.
func serverOnlyDial(outbound adapter.Outbound) bool {
	switch outbound.Type() {
	case C.TypeVLESS, C.TypeVMess, C.TypeTrojan, C.TypeShadowsocks, C.TypeShadowTLS,
		C.TypeHysteria, C.TypeHysteria2, C.TypeTUIC, C.TypeAnyTLS, C.TypeNaive:
		return true
	default:
		return false
	}
}

// memberFailed judges a failed dial through member, begun at start, or a failed handshake
// write (start is zero).
func (g *URLTestGroup) memberFailed(ctx context.Context, member adapter.Outbound, network string, err error, start time.Time) {
	// A reset, an EOF, a closed pipe or a timeout are the member's: E.IsClosedOrCanceled
	// counts them as closed, which suits a copy loop, not this. A timeout stays the
	// member's even when it also reports itself closed: the idle and handshake timeouts of
	// quic-go (Hysteria2, TUIC) match net.ErrClosed.
	var netErr net.Error
	timeout := errors.As(err, &netErr) && netErr.Timeout()
	if ctx.Err() != nil || !timeout && (errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed)) {
		return
	}
	tag := RealTag(member)
	if !start.IsZero() && g.succeededSince(tag, start) {
		g.logger.Debug("outbound ", tag, " failed while another connection through it succeeded: ", err)
		return
	}
	if g.history.LoadURLTestHistory(tag) != nil {
		if network != N.NetworkTCP || !serverOnlyDial(member) {
			g.confirmFailure(tag, member)
			return
		}
		g.logger.Info("outbound ", tag, " unavailable: ", err)
		g.history.DeleteURLTestHistory(tag)
	}
	g.requestUpdateCheck()
}

// memberSucceeded records a successful TCP dial through member.
func (g *URLTestGroup) memberSucceeded(member adapter.Outbound) {
	tag := RealTag(member)
	value, loaded := g.successes.Load(tag)
	if !loaded {
		value, _ = g.successes.LoadOrStore(tag, new(atomic.Int64))
	}
	value.(*atomic.Int64).Store(int64(time.Since(g.epoch)))
}

// succeededSince reports whether a TCP dial through the member succeeded after start.
func (g *URLTestGroup) succeededSince(tag string, start time.Time) bool {
	value, loaded := g.successes.Load(tag)
	return loaded && value.(*atomic.Int64).Load() > int64(start.Sub(g.epoch))
}

// requestUpdateCheck selects again in the background; failures that come while a selection
// waits to run are covered by it, so at most one selection waits at any time (a selection
// may run long: the download test).
func (g *URLTestGroup) requestUpdateCheck() {
	if g.updatePending.Swap(true) {
		return
	}
	go func() {
		g.updateAccess.Lock()
		defer g.updateAccess.Unlock()
		g.updatePending.Store(false)
		g.updateSelection()
	}()
}

type memberConfirm struct {
	running     bool
	notBefore   time.Time
	pause       time.Duration
	lastFailure time.Time
}

// confirmFailure has one URL test of the member tell its failure from the destination's,
// and reports whether it started one.
// The test is the periodic one, with its timeout; a failed test makes the member
// unavailable, and the group selects again. A test that finds the member working changes
// nothing (the periodic test keeps its schedule), but delays the next one: as long as the
// test took, then twice as long after each false alarm, at most an interval, after which
// the periodic test covers the member anyway. The delays grow for as long as failures keep
// coming, tested or not, and start over after an interval without any. A false alarm that
// persists, like an application calling a dead site again and again, so costs at most one
// test per interval, as many as the periodic test, while an isolated one leaves the member
// unwatched only for the length of a test.
func (g *URLTestGroup) confirmFailure(tag string, member adapter.Outbound) bool {
	return g.confirmWith(&g.confirms, tag, member)
}

// confirmUnanswered is confirmFailure for connections that got no answer (see
// urltest_response.go), with pauses of its own: a quiet router whose traffic goes to dead
// destinations keeps the member passing these tests, and must not delay the tests of
// failed dials.
func (g *URLTestGroup) confirmUnanswered(tag string, member adapter.Outbound) bool {
	return g.confirmWith(&g.unansweredConfirms, tag, member)
}

func (g *URLTestGroup) confirmWith(confirms *map[string]*memberConfirm, tag string, member adapter.Outbound) bool {
	now := time.Now()
	g.confirmAccess.Lock()
	if *confirms == nil {
		*confirms = make(map[string]*memberConfirm)
	}
	state := (*confirms)[tag]
	if state == nil {
		state = &memberConfirm{}
		(*confirms)[tag] = state
	}
	if now.Sub(state.lastFailure) > g.interval {
		state.pause, state.notBefore = 0, time.Time{}
	}
	state.lastFailure = now
	if state.running || now.Before(state.notBefore) {
		g.confirmAccess.Unlock()
		return false
	}
	state.running = true
	g.confirmAccess.Unlock()
	go func() {
		start := time.Now()
		_, err := testOutbound(g.ctx, g.link, member)
		now := time.Now()
		g.confirmAccess.Lock()
		state.running = false
		if err == nil {
			state.pause = min(max(2*state.pause, now.Sub(start)), g.interval)
			state.notBefore = now.Add(state.pause)
		}
		g.confirmAccess.Unlock()
		if err == nil {
			g.memberTestPassed(tag, start)
		}
		if err == nil || g.ctx.Err() != nil {
			return
		}
		g.logger.Info("outbound ", tag, " unavailable: ", err)
		g.history.DeleteURLTestHistory(tag)
		g.performUpdateCheck()
	}()
	return true
}

// testOutbound runs one URL test of detour, bounded by the TCP timeout.
func testOutbound(ctx context.Context, link string, detour adapter.Outbound) (uint16, error) {
	ctx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	type result struct {
		delay uint16
		err   error
	}
	done := make(chan result, 1)
	go func() {
		delay, err := urltest.URLTest(ctx, link, detour)
		done <- result{delay, err}
	}()
	select {
	case r := <-done:
		return r.delay, r.err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// handshakeConn reports a failed write that carried the handshake a dial deferred
// (N.NeedHandshakeForWrite), then gets out of the way: once the handshake has gone out it is
// replaceable, and the copy loop writes to the connection under it directly.
type handshakeConn struct {
	net.Conn
	done    atomic.Bool
	failed  func(error)
	writing func() // called before a write that carries data, until the handshake is done
}

func (c *handshakeConn) Write(b []byte) (int, error) {
	if c.writing != nil && len(b) > 0 && !c.done.Load() {
		c.writing()
	}
	n, err := c.Conn.Write(b)
	if c.done.Load() {
		return n, err
	}
	if err == nil {
		if !N.NeedHandshakeForWrite(c.Conn) {
			c.done.Store(true)
		}
	} else if len(b) > 0 || !(E.IsMulti(err, os.ErrInvalid, context.DeadlineExceeded, io.EOF) || E.IsTimeout(err)) {
		// the connection manager kicks the handshake with an empty write under a short
		// deadline and does not count its timeout as a failure; the write with payload decides
		if !c.done.Swap(true) {
			c.failed(err)
		}
	}
	return n, err
}

func (c *handshakeConn) ReaderReplaceable() bool {
	return true
}

func (c *handshakeConn) WriterReplaceable() bool {
	return c.done.Load()
}

func (c *handshakeConn) Upstream() any {
	return c.Conn
}

package group

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Members that accept connections but never answer them (podkop-engine).
//
// A Hysteria2 or TUIC server that went silent still opens streams (locally, 0-RTT
// included), and a VLESS or Trojan server whose own outbound is dead still accepts and
// handshakes: the dial succeeds, the first write too, the answer never comes. The group
// therefore watches the first answer of every TCP connection through a member.
//
// A connection is overdue when no byte of the answer has come one retransmission timeout
// after the client's last write, the timeout computed as RFC 6298 does for TCP, from the
// first-byte latencies of the member's own connections:
//
//	RTO = SRTT + 4 * RTTVAR + 1 s, at most C.TCPTimeout
//
// with SRTT and RTTVAR seeded from the member's last URL test delay (an upper bound: the
// test takes two or three round trips), the second added for one retransmitted SYN on the
// server's side (the initial RTO of RFC 6298 and Linux), the bound being the timeout
// sing-box gives a handshake and the URL test. The clock runs from the last write: a
// first flight may go out in pieces (tls_fragment waits between them), and the server
// answers the whole. As in Karn's algorithm a late answer is no sample; it doubles the
// timeout until an answer comes in time (RFC 6298, 5.5). A connection that fails before
// the first byte (reset, aborted, or timed out on the way, not by a deadline of the caller)
// counts at once; an EOF, or an error the server sent back (a destination it could not
// reach), does not.
//
// An overdue connection says the member may be dead, or the destination slow. It is
// refuted, as a failed dial is in S1, when a connection whose last write came later got an
// answer, or a test of the member that began later passed. Otherwise one URL test of the
// member decides, with the pauses after false alarms of confirmFailure kept apart from
// those of S1, and a destination that was overdue while the member passed counts no more
// for an interval. When the group has switched away from a member that lost its test
// result, it closes the member's connections that never got an answer, preconnects
// included: they would hang until their own timeouts, and the applications retry through
// the new member at once. UDP is not watched. All times are offsets from the epoch of the
// group, on the monotonic clock: the router's clock steps at the first NTP sync.

const (
	responseWaiting uint32 = iota
	responseAnswered
	responseClosed
)

type memberResponses struct {
	access        sync.Mutex
	smoothed      time.Duration
	variation     time.Duration
	seeded        bool
	backoff       uint
	answeredWrite time.Duration // the latest last write among the connections that got an answer
	testPassed    time.Duration // the latest start of a passed test of the member
	pending       map[*responseConn]struct{}
	evidence      map[*responseConn]struct{}
	passedHosts   map[string]time.Duration // destination → until when its silence counts no more
}

type responseConn struct {
	net.Conn
	group     *URLTestGroup
	member    adapter.Outbound
	tag       string
	responses *memberResponses
	host      string
	dialedAt  time.Duration
	state     atomic.Uint32
	lastWrite atomic.Int64 // the last write before the answer, as an offset from the epoch; 0 before any
	timer     *time.Timer  // under responses.access
}

// watchResponses says whether the first answers through member are watched: proxies with
// a test result. A direct member is our own connection, a group watches its own members.
func watchResponses(member adapter.Outbound) bool {
	if _, isGroup := member.(adapter.OutboundGroup); isGroup {
		return false
	}
	switch member.Type() {
	case C.TypeDirect, C.TypeBlock, C.TypeDNS:
		return false
	}
	return true
}

func (g *URLTestGroup) now() time.Duration {
	return time.Since(g.epoch)
}

func (g *URLTestGroup) memberResponses(tag string) *memberResponses {
	value, loaded := g.responses.Load(tag)
	if !loaded {
		value, _ = g.responses.LoadOrStore(tag, &memberResponses{
			pending:     make(map[*responseConn]struct{}),
			evidence:    make(map[*responseConn]struct{}),
			passedHosts: make(map[string]time.Duration),
		})
	}
	return value.(*memberResponses)
}

// watchResponse wraps a TCP connection dialed through member.
func (g *URLTestGroup) watchResponse(conn net.Conn, member adapter.Outbound, destination M.Socksaddr) net.Conn {
	if !watchResponses(member) {
		return conn
	}
	tag := RealTag(member)
	if g.history.LoadURLTestHistory(tag) == nil {
		return conn
	}
	responses := g.memberResponses(tag)
	watched := &responseConn{
		Conn:      conn,
		group:     g,
		member:    member,
		tag:       tag,
		responses: responses,
		host:      destination.AddrString(),
		dialedAt:  g.now(),
	}
	responses.access.Lock()
	responses.pending[watched] = struct{}{}
	responses.access.Unlock()
	return watched
}

// retransmissionTimeout is under responses.access.
func (g *URLTestGroup) retransmissionTimeout(responses *memberResponses, tag string) time.Duration {
	if !responses.seeded {
		if history := g.history.LoadURLTestHistory(tag); history != nil {
			sample := time.Duration(history.Delay) * time.Millisecond
			responses.smoothed, responses.variation, responses.seeded = sample, sample/2, true
		}
	}
	timeout := responses.smoothed + 4*responses.variation + time.Second
	for i := uint(0); i < responses.backoff && timeout < C.TCPTimeout; i++ {
		timeout *= 2
	}
	return min(timeout, C.TCPTimeout)
}

// sample adds a first-byte latency (RFC 6298, 2.2 and 2.3), under responses.access.
func (responses *memberResponses) sample(latency time.Duration) {
	if !responses.seeded {
		responses.smoothed, responses.variation, responses.seeded = latency, latency/2, true
		return
	}
	difference := responses.smoothed - latency
	if difference < 0 {
		difference = -difference
	}
	responses.variation = (3*responses.variation + difference) / 4
	responses.smoothed = (7*responses.smoothed + latency) / 8
}

// wrote records a write of the client before the answer; the first one starts the clock.
func (c *responseConn) wrote() {
	if c.state.Load() != responseWaiting {
		return
	}
	if c.lastWrite.Swap(int64(max(c.group.now(), 1))) != 0 {
		return
	}
	c.responses.access.Lock()
	if c.state.Load() == responseWaiting && c.timer == nil {
		c.timer = time.AfterFunc(c.group.retransmissionTimeout(c.responses, c.tag), c.expired)
	}
	c.responses.access.Unlock()
}

func (c *responseConn) expired() {
	if c.group.responsesClosed.Load() {
		return
	}
	responses := c.responses
	responses.access.Lock()
	if c.state.Load() != responseWaiting {
		responses.access.Unlock()
		return
	}
	lastWrite := time.Duration(c.lastWrite.Load())
	if remaining := lastWrite + c.group.retransmissionTimeout(responses, c.tag) - c.group.now(); remaining > 0 {
		c.timer.Reset(remaining) // the client wrote again meanwhile
		responses.access.Unlock()
		return
	}
	confirm := c.group.addEvidence(c, lastWrite)
	responses.access.Unlock()
	if confirm && c.group.confirmUnanswered(c.tag, c.member) {
		c.group.logger.Info("outbound ", c.tag, ": no answer from ", c.host, " after ", (c.group.now() - lastWrite).Round(time.Millisecond), ", testing the outbound")
	}
}

// addEvidence records that c went unanswered since lastWrite, under responses.access, and
// reports whether the member is to be tested.
func (g *URLTestGroup) addEvidence(c *responseConn, lastWrite time.Duration) bool {
	responses := c.responses
	if responses.answeredWrite > lastWrite || responses.testPassed > lastWrite {
		return false
	}
	history := g.history.LoadURLTestHistory(c.tag)
	if history == nil {
		return false // already unavailable
	}
	if testStart := history.Time.Add(-time.Duration(history.Delay) * time.Millisecond).Sub(g.epoch); testStart > lastWrite {
		return false
	}
	if until, passed := responses.passedHosts[c.host]; passed && g.now() < until {
		return false
	}
	responses.evidence[c] = struct{}{}
	return true
}

// memberTestPassed refutes the evidence older than a passed test of the member that began
// at start, and lets the destinations it was about count no more for an interval.
func (g *URLTestGroup) memberTestPassed(tag string, start time.Time) {
	value, loaded := g.responses.Load(tag)
	if !loaded {
		return
	}
	responses := value.(*memberResponses)
	began := start.Sub(g.epoch)
	now := g.now()
	responses.access.Lock()
	defer responses.access.Unlock()
	responses.testPassed = max(responses.testPassed, began)
	for host, until := range responses.passedHosts {
		if now >= until {
			delete(responses.passedHosts, host)
		}
	}
	for c := range responses.evidence {
		if time.Duration(c.lastWrite.Load()) < began {
			responses.passedHosts[c.host] = now + g.interval
			delete(responses.evidence, c)
		}
	}
}

func (c *responseConn) answered() {
	if !c.state.CompareAndSwap(responseWaiting, responseAnswered) {
		return
	}
	now := c.group.now()
	responses := c.responses
	responses.access.Lock()
	defer responses.access.Unlock()
	delete(responses.pending, c)
	if c.timer != nil {
		c.timer.Stop()
	}
	start := c.dialedAt
	if written := time.Duration(c.lastWrite.Load()); written != 0 {
		start = written
		if _, wasOverdue := responses.evidence[c]; wasOverdue {
			delete(responses.evidence, c)
			responses.backoff++ // Karn: no sample from a late answer
		} else if latency := now - start; latency > 0 {
			responses.sample(latency)
			responses.backoff = 0
		}
	}
	responses.answeredWrite = max(responses.answeredWrite, start)
	for evidence := range responses.evidence {
		if time.Duration(evidence.lastWrite.Load()) < start {
			delete(responses.evidence, evidence)
		}
	}
}

// failedOnTheWay tells a failure of the way to the server (a reset, an abort, a timeout
// that no deadline of the caller set) from an error the server sent back or an EOF.
func failedOnTheWay(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ETIMEDOUT) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// failedBeforeAnswer handles a read error before the first byte.
func (c *responseConn) failedBeforeAnswer(err error) {
	if c.group.responsesClosed.Load() || c.state.Load() != responseWaiting || errors.Is(err, io.EOF) || !failedOnTheWay(err) {
		return
	}
	responses := c.responses
	responses.access.Lock()
	lastWrite := time.Duration(c.lastWrite.Load())
	if lastWrite == 0 {
		lastWrite = c.dialedAt
	}
	confirm := c.group.addEvidence(c, lastWrite)
	responses.access.Unlock()
	if confirm && c.group.confirmUnanswered(c.tag, c.member) {
		c.group.logger.Info("outbound ", c.tag, ": ", c.host, " failed before any answer: ", err, ", testing the outbound")
	}
}

// observeRead notes what a read before the answer brought.
func (c *responseConn) observeRead(n int, err error) {
	if c.state.Load() != responseWaiting {
		return
	}
	if n > 0 {
		c.answered()
	} else if err != nil {
		c.failedBeforeAnswer(err)
	}
}

func (c *responseConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.observeRead(n, err)
	return n, err
}

func (c *responseConn) Write(b []byte) (int, error) {
	if len(b) > 0 {
		c.wrote()
	}
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.wrote()
	}
	return n, err
}

// The copy loop writes below this connection, so it reports its writes through a counter.
// It reads through this connection until the answer begins, then below it; until then a
// read waiter of the connection below, when there is one, still waits without a buffer.

func (c *responseConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return c.Conn, []N.CountFunc{func(n int64) {
		if n > 0 {
			c.wrote()
		}
	}}
}

func (c *responseConn) CreateReadWaiter() (N.ReadWaiter, bool) {
	readWaiter, created := bufio.CreateReadWaiter(c.Conn)
	if !created || c.state.Load() != responseWaiting {
		return readWaiter, created
	}
	return &responseReadWaiter{ReadWaiter: readWaiter, conn: c}, true
}

type responseReadWaiter struct {
	N.ReadWaiter
	conn *responseConn
}

func (w *responseReadWaiter) WaitReadBuffer() (*buf.Buffer, error) {
	buffer, err := w.ReadWaiter.WaitReadBuffer()
	n := 0
	if buffer != nil {
		n = buffer.Len()
	}
	w.conn.observeRead(n, err)
	return buffer, err
}

func (c *responseConn) NeedHandshakeForRead() bool {
	return c.state.Load() == responseWaiting
}

func (c *responseConn) ReaderReplaceable() bool {
	return c.state.Load() != responseWaiting
}

func (c *responseConn) WriterReplaceable() bool {
	return true
}

func (c *responseConn) Upstream() any {
	return c.Conn
}

func (c *responseConn) Close() error {
	if c.state.Swap(responseClosed) != responseClosed {
		responses := c.responses
		responses.access.Lock()
		delete(responses.pending, c)
		delete(responses.evidence, c)
		if c.timer != nil {
			c.timer.Stop()
		}
		responses.access.Unlock()
	}
	return c.Conn.Close()
}

// closeUnanswered closes the connections that never got an answer through the members the
// group has switched away from after they lost their test result: their answers will not
// come. When every member is down the selection stays, and so do its connections.
func (g *URLTestGroup) closeUnanswered() {
	selected := g.selectedOutboundTCP.Load()
	var unanswered []*responseConn
	g.responses.Range(func(key, value any) bool {
		tag := key.(string)
		if g.history.LoadURLTestHistory(tag) != nil || (selected != nil && RealTag(selected) == tag) {
			return true
		}
		responses := value.(*memberResponses)
		responses.access.Lock()
		for c := range responses.pending {
			unanswered = append(unanswered, c)
		}
		responses.access.Unlock()
		return true
	})
	if len(unanswered) == 0 {
		return
	}
	g.logger.Debug("closing ", len(unanswered), " connections that got no answer through outbounds switched away from")
	go func() {
		// a close may wait (a TLS close_notify, a FIN of a multiplexed stream): not under
		// the lock of the selection
		for _, c := range unanswered {
			c.Close()
		}
	}()
}

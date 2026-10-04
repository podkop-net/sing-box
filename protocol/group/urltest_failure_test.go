package group

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

func dialRefused(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, syscall.ECONNREFUSED
}

// newTestURLTest makes a group of members, the first one selected (fastest by history).
func newTestURLTest(t *testing.T, link string, members ...*testMember) (*URLTest, *URLTestGroup) {
	history := urltest.NewHistoryStorage()
	ctx := service.ContextWithPtr(context.Background(), history)
	outbounds := make([]adapter.Outbound, len(members))
	for i, member := range members {
		outbounds[i] = member
		history.StoreURLTestHistory(member.Tag(), &adapter.URLTestHistory{Time: time.Now(), Delay: uint16(10 + 100*i)})
	}
	group, err := NewURLTestGroup(ctx, nil, log.NewNOPFactory().Logger(), outbounds, nil, link, "", time.Minute, 50, 0, false)
	require.NoError(t, err)
	group.performUpdateCheck()
	require.Equal(t, members[0].Tag(), group.selectedOutboundTCP.Load().Tag())
	return &URLTest{group: group, logger: log.NewNOPFactory().NewLogger("urltest")}, group
}

func waitSelected(t *testing.T, group *URLTestGroup, tag string) {
	t.Helper()
	require.Eventually(t, func() bool {
		return group.selectedOutboundTCP.Load().Tag() == tag
	}, 2*time.Second, 5*time.Millisecond, "selected outbound is not %s", tag)
}

func confirmState(group *URLTestGroup, tag string) (memberConfirm, bool) {
	group.confirmAccess.Lock()
	defer group.confirmAccess.Unlock()
	state := group.confirms[tag]
	if state == nil {
		return memberConfirm{}, false
	}
	return *state, true
}

func waitConfirmed(t *testing.T, group *URLTestGroup, tag string) memberConfirm {
	t.Helper()
	require.Eventually(t, func() bool {
		state, loaded := confirmState(group, tag)
		return loaded && !state.running
	}, 2*time.Second, 5*time.Millisecond)
	state, _ := confirmState(group, tag)
	return state
}

// allowConfirm ends the pause before the next test, as if the time had passed, with the
// member's last failure at lastFailure.
func allowConfirm(group *URLTestGroup, tag string, lastFailure time.Time) {
	group.confirmAccess.Lock()
	defer group.confirmAccess.Unlock()
	group.confirms[tag].notBefore = time.Time{}
	group.confirms[tag].lastFailure = lastFailure
}

// A protocol that contacts only its server failed to dial: that is a failed URL test of
// the member, the group switches at once and does not test it again.
func TestURLTestServerFailureSwitches(t *testing.T) {
	link, requests := testURL(t, 0)
	dead := newTestMember(C.TypeVLESS, "dead", dialRefused)
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, dead, spare)

	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	waitSelected(t, group, "spare")
	require.Nil(t, group.history.LoadURLTestHistory("dead"))
	require.Equal(t, int32(1), dead.dials.Load(), "the failed member was tested again")
	require.Equal(t, int32(0), requests.Load())
}

// A server that drops the connection attempts makes the dial time out (its own connect
// timeout, the caller still waiting): the most common way a blocked server fails, and the
// server's failure, not a canceled dial.
func TestURLTestDialTimeoutSwitches(t *testing.T) {
	link, _ := testURL(t, 0)
	blackholed := newTestMember(C.TypeVLESS, "blackholed", func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	})
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, blackholed, spare)

	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	waitSelected(t, group, "spare")
}

// quicIdleTimeout is the error quic-go gives when the server went silent: a timeout that
// also matches net.ErrClosed.
type quicIdleTimeout struct{}

func (quicIdleTimeout) Error() string        { return "timeout: no recent network activity" }
func (quicIdleTimeout) Timeout() bool        { return true }
func (quicIdleTimeout) Temporary() bool      { return false }
func (quicIdleTimeout) Is(target error) bool { return target == net.ErrClosed }

// A Hysteria2 or TUIC server went silent: the QUIC connection times out and the dial fails
// with an error that also reports itself closed. It is the server's failure, not a close
// the caller made.
func TestURLTestQUICTimeoutSwitches(t *testing.T) {
	link, _ := testURL(t, 0)
	silent := newTestMember(C.TypeHysteria2, "silent", func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		return nil, quicIdleTimeout{}
	})
	spare := newTestMember(C.TypeHysteria2, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, silent, spare)

	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.ErrorIs(t, err, net.ErrClosed)
	waitSelected(t, group, "spare")
}

// A socks member failed to reach one destination but works: one URL test proves it, the
// group keeps it and its test result (the periodic test keeps its schedule), and the test
// is not repeated for every failed connection. Each false alarm doubles the pause before
// the next test, never beyond the interval; after an interval without failures the pause
// starts over from the length of the test.
func TestURLTestDestinationFailureKeepsMember(t *testing.T) {
	link, requests := testURL(t, 100*time.Millisecond)
	deadSite := M.ParseSocksaddr("1.2.3.4:443")
	socks := newTestMember(C.TypeSOCKS, "socks", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if destination == deadSite {
			return nil, syscall.ECONNREFUSED
		}
		return dialWorking(ctx, network, destination)
	})
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, socks, spare)
	tested := group.history.LoadURLTestHistory("socks").Time

	for range 20 { // a burst of failing connections while the test runs
		_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, deadSite)
		require.Error(t, err)
	}
	first := waitConfirmed(t, group, "socks")
	require.Equal(t, int32(1), requests.Load(), "one URL test for the whole burst")
	require.Equal(t, "socks", group.selectedOutboundTCP.Load().Tag())
	require.Equal(t, tested, group.history.LoadURLTestHistory("socks").Time, "the test result was replaced")
	require.GreaterOrEqual(t, first.pause, 100*time.Millisecond, "the pause is shorter than the test")
	require.Less(t, first.pause, time.Second)
	_, _ = urlTest.DialContext(context.Background(), N.NetworkTCP, deadSite)
	time.Sleep(20 * time.Millisecond)
	require.Equal(t, int32(1), requests.Load(), "tested again within the pause")

	allowConfirm(group, "socks", time.Now())
	_, _ = urlTest.DialContext(context.Background(), N.NetworkTCP, deadSite)
	require.Eventually(t, func() bool { return requests.Load() == 2 }, 2*time.Second, 5*time.Millisecond)
	second := waitConfirmed(t, group, "socks")
	require.GreaterOrEqual(t, second.pause, 2*first.pause)
	require.LessOrEqual(t, second.pause, group.interval)

	allowConfirm(group, "socks", time.Now().Add(-group.interval-time.Second))
	_, _ = urlTest.DialContext(context.Background(), N.NetworkTCP, deadSite)
	require.Eventually(t, func() bool { return requests.Load() == 3 }, 2*time.Second, 5*time.Millisecond)
	third := waitConfirmed(t, group, "socks")
	require.Less(t, third.pause, 2*second.pause, "the pause did not start over after an interval without failures")
}

// A false alarm that persists keeps the pause at the interval, though the tests themselves
// are then an interval apart: the failures in between, not tested, count.
func TestURLTestPersistentFalseAlarm(t *testing.T) {
	link, requests := testURL(t, 0)
	deadSite := M.ParseSocksaddr("1.2.3.4:443")
	socks := newTestMember(C.TypeSOCKS, "socks", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if destination == deadSite {
			return nil, syscall.ECONNREFUSED
		}
		return dialWorking(ctx, network, destination)
	})
	urlTest, group := newTestURLTest(t, link, socks, newTestMember(C.TypeVLESS, "spare", dialWorking))

	_, _ = urlTest.DialContext(context.Background(), N.NetworkTCP, deadSite)
	waitConfirmed(t, group, "socks")
	group.confirmAccess.Lock()
	group.confirms["socks"].pause = group.interval  // the pause has grown to the interval
	group.confirms["socks"].notBefore = time.Time{} // and has passed, a failure every second
	group.confirms["socks"].lastFailure = time.Now().Add(-time.Second)
	group.confirmAccess.Unlock()
	_, _ = urlTest.DialContext(context.Background(), N.NetworkTCP, deadSite)
	require.Eventually(t, func() bool { return requests.Load() == 2 }, 2*time.Second, 5*time.Millisecond)
	state := waitConfirmed(t, group, "socks")
	require.Equal(t, group.interval, state.pause, "the pause started over while the false alarm went on")
}

// A dial that fails while another dial through the same member succeeds says nothing: the
// member was reachable meanwhile. Not even a socks member is tested for it.
func TestURLTestFailureRefutedBySuccess(t *testing.T) {
	for _, memberType := range []string{C.TypeVLESS, C.TypeSOCKS} {
		t.Run(memberType, func(t *testing.T) {
			link, requests := testURL(t, 0)
			deadSite := M.ParseSocksaddr("1.2.3.4:443")
			release := make(chan struct{})
			member := newTestMember(memberType, "member", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
				if destination == deadSite {
					<-release // fails once the other dial has succeeded
					return nil, syscall.ECONNREFUSED
				}
				return dialWorking(ctx, network, destination)
			})
			urlTest, group := newTestURLTest(t, link, member, newTestMember(C.TypeVLESS, "spare", dialWorking))

			failed := make(chan error, 1)
			go func() {
				_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, deadSite)
				failed <- err
			}()
			require.Eventually(t, func() bool { return member.dials.Load() == 1 }, 2*time.Second, time.Millisecond, "the failing dial has not begun")
			conn, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr(link[len("http://"):]))
			require.NoError(t, err)
			conn.Close()
			close(release)
			require.Error(t, <-failed)
			time.Sleep(50 * time.Millisecond)
			require.Equal(t, "member", group.selectedOutboundTCP.Load().Tag())
			require.NotNil(t, group.history.LoadURLTestHistory("member"))
			_, tested := confirmState(group, "member")
			require.False(t, tested)
			require.Equal(t, int32(0), requests.Load())
		})
	}
}

// A success before the failed dial began refutes nothing: the member may have died since.
func TestURLTestEarlierSuccessDoesNotRefute(t *testing.T) {
	link, _ := testURL(t, 0)
	var dead atomic.Bool
	member := newTestMember(C.TypeVLESS, "member", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if dead.Load() {
			return nil, syscall.ECONNREFUSED
		}
		return dialWorking(ctx, network, destination)
	})
	urlTest, group := newTestURLTest(t, link, member, newTestMember(C.TypeVLESS, "spare", dialWorking))

	conn, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr(link[len("http://"):]))
	require.NoError(t, err)
	conn.Close()
	dead.Store(true)
	_, err = urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	waitSelected(t, group, "spare")
}

// A socks member that is really down fails its URL test too: the group switches.
func TestURLTestDestinationFailureConfirmedDown(t *testing.T) {
	link, _ := testURL(t, 0)
	socks := newTestMember(C.TypeSOCKS, "socks", dialRefused)
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, socks, spare)

	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	waitSelected(t, group, "spare")
	require.Nil(t, group.history.LoadURLTestHistory("socks"))
}

// A failed packet listen is not what the URL test, made over TCP, does: even for a protocol
// that contacts only its server, the test decides.
func TestURLTestPacketFailureConfirms(t *testing.T) {
	link, requests := testURL(t, 0)
	member := newTestMember(C.TypeHysteria2, "member", dialWorking)
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, member, spare)

	_, err := urlTest.ListenPacket(context.Background(), M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	waitConfirmed(t, group, "member")
	require.Equal(t, int32(1), requests.Load())
	require.Equal(t, "member", group.selectedOutboundUDP.Load().Tag())
	require.NotNil(t, group.history.LoadURLTestHistory("member"))
}

// A member already without a test result is not tested on its failures; the group only
// makes sure an available member is selected.
func TestURLTestUnavailableMemberNotTested(t *testing.T) {
	link, requests := testURL(t, 0)
	socks := newTestMember(C.TypeSOCKS, "socks", dialRefused)
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, socks, spare)
	group.history.DeleteURLTestHistory("socks") // as by another group's failed test

	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	waitSelected(t, group, "spare")
	_, tested := confirmState(group, "socks")
	require.False(t, tested)
	require.Equal(t, int32(0), requests.Load())
}

// Our own network is down: every member fails in turn. The group ends on the last one and
// stays there, with nothing more to test until the periodic test.
func TestURLTestAllMembersDown(t *testing.T) {
	link, requests := testURL(t, 0)
	first := newTestMember(C.TypeVLESS, "first", dialRefused)
	second := newTestMember(C.TypeSOCKS, "second", dialRefused)
	urlTest, group := newTestURLTest(t, link, first, second)

	_, _ = urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	waitSelected(t, group, "second")
	_, _ = urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	waitConfirmed(t, group, "second")
	require.Nil(t, group.history.LoadURLTestHistory("second"))
	require.Equal(t, int32(0), requests.Load())
	for range 10 {
		_, _ = urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	}
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, "second", group.selectedOutboundTCP.Load().Tag())
	require.Equal(t, int32(12), second.dials.Load(), "an unavailable member was tested: 11 connections, 1 test expected")
}

// A dial the caller canceled says nothing about the member.
func TestURLTestCanceledDialIgnored(t *testing.T) {
	link, requests := testURL(t, 0)
	member := newTestMember(C.TypeVLESS, "member", func(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
		return nil, ctx.Err()
	})
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, member, spare)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := urlTest.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, "member", group.selectedOutboundTCP.Load().Tag())
	require.NotNil(t, group.history.LoadURLTestHistory("member"))
	require.Equal(t, int32(0), requests.Load())
}

// lazyConn defers its protocol handshake to the first write that succeeds, like VLESS or
// Trojan early connections and transports that connect on the first write.
type lazyConn struct {
	net.Conn
	writeErrs  []error
	handshaken atomic.Bool
}

func (c *lazyConn) NeedHandshakeForWrite() bool {
	return !c.handshaken.Load()
}

func (c *lazyConn) Write(b []byte) (int, error) {
	if len(c.writeErrs) > 0 {
		err := c.writeErrs[0]
		c.writeErrs = c.writeErrs[1:]
		if err != nil {
			return 0, err
		}
	}
	c.handshaken.Store(true)
	return len(b), nil
}

func newLazyMember(t *testing.T, writeErrs ...error) *testMember {
	local, remote := net.Pipe()
	t.Cleanup(func() { local.Close(); remote.Close() })
	return newTestMember(C.TypeVLESS, "member", func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		return &lazyConn{Conn: local, writeErrs: writeErrs}, nil
	})
}

func wrapperInWritePath(conn net.Conn) bool {
	writer, _ := N.UnwrapCountWriter(conn, nil)
	_, isWrapper := writer.(*handshakeConn)
	return isWrapper
}

// The write that carries the handshake fails: as for a failed dial, the group switches.
// The write reaches the wrapper the way the connection manager performs it, and afterwards
// the wrapper is replaceable, out of the copy loop's way.
func TestURLTestHandshakeWriteFailure(t *testing.T) {
	link, _ := testURL(t, 0)
	urlTest, group := newTestURLTest(t, link, newLazyMember(t, syscall.ECONNRESET), newTestMember(C.TypeVLESS, "spare", dialWorking))

	conn, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.NoError(t, err)
	require.True(t, N.NeedHandshakeForWrite(conn))
	require.True(t, wrapperInWritePath(conn))
	writer, _ := N.UnwrapCountWriter(conn, nil) // as kickWriteHandshake does
	_, err = writer.Write([]byte("payload"))
	require.ErrorIs(t, err, syscall.ECONNRESET)
	waitSelected(t, group, "spare")
	require.False(t, wrapperInWritePath(conn), "the wrapper stays in the write path after the handshake")
}

// The connection manager kicks the handshake with an empty write under a short deadline;
// its timeout is no failure, the write with payload that follows decides.
func TestURLTestHandshakeKickTimeout(t *testing.T) {
	link, _ := testURL(t, 0)
	urlTest, group := newTestURLTest(t, link, newLazyMember(t, os.ErrDeadlineExceeded, syscall.ECONNRESET), newTestMember(C.TypeVLESS, "spare", dialWorking))

	conn, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.NoError(t, err)
	writer, _ := N.UnwrapCountWriter(conn, nil)
	_, err = writer.Write(nil)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	time.Sleep(20 * time.Millisecond)
	require.Equal(t, "member", group.selectedOutboundTCP.Load().Tag())
	require.True(t, wrapperInWritePath(conn))
	_, err = writer.Write([]byte("payload"))
	require.ErrorIs(t, err, syscall.ECONNRESET)
	waitSelected(t, group, "spare")
}

// The handshake went out: nothing is reported and the wrapper leaves the write path.
func TestURLTestHandshakeWriteSuccess(t *testing.T) {
	link, _ := testURL(t, 0)
	urlTest, group := newTestURLTest(t, link, newLazyMember(t), newTestMember(C.TypeVLESS, "spare", dialWorking))

	conn, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.NoError(t, err)
	writer, _ := N.UnwrapCountWriter(conn, nil)
	_, err = writer.Write([]byte("payload"))
	require.NoError(t, err)
	require.False(t, wrapperInWritePath(conn))
	time.Sleep(20 * time.Millisecond)
	require.Equal(t, "member", group.selectedOutboundTCP.Load().Tag())
}

// A connection that is not lazy is not wrapped at all.
func TestURLTestEagerConnNotWrapped(t *testing.T) {
	link, _ := testURL(t, 0)
	member := newTestMember(C.TypeVLESS, "member", dialWorking)
	urlTest, _ := newTestURLTest(t, link, member)
	conn, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr(link[len("http://"):]))
	require.NoError(t, err)
	defer conn.Close()
	writer, _ := N.UnwrapCountWriter(conn, nil)
	_, isWrapper := writer.(*handshakeConn)
	require.False(t, isWrapper)
	_, isTCP := writer.(*net.TCPConn)
	require.True(t, isTCP, "the copy loop does not reach the connection itself: %T", writer)
}

// Dials read the selection while failures change it, through members of different types:
// the selection is stored atomically (run with -race).
func TestURLTestSelectionConcurrentSwitch(t *testing.T) {
	link, _ := testURL(t, 0)
	first := newTestMember(C.TypeVLESS, "first", dialRefused)
	second := newTestMember(C.TypeHysteria2, "second", dialRefused)
	urlTest, group := newTestURLTest(t, link, first, second)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
				_ = urlTest.Now()
			}
		}()
	}
	for i := range 50 {
		group.history.StoreURLTestHistory("first", &adapter.URLTestHistory{Time: time.Now(), Delay: uint16(10 + 200*(i%2))})
		group.history.StoreURLTestHistory("second", &adapter.URLTestHistory{Time: time.Now(), Delay: 110})
		group.performUpdateCheck()
	}
	close(stop)
	wg.Wait()
}

var _ io.Writer = (*handshakeConn)(nil)

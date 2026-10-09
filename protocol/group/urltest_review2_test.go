package group

import (
	"context"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// What the second review of the group showed.

// A reset of the network (a new default interface, the connections closed by hand) ends
// the dials in flight with errors of its own, and comes a moment after the monitor's
// word, or with none. The failure is the reset's: the group stays on the member.
func TestURLTestFailureAcrossANetworkReset(t *testing.T) {
	// a delay that is not zero: a result of 0 ms counts as none when the group selects
	link, requests := testURL(t, 20*time.Millisecond)
	var (
		urlTest *URLTest
		reset   atomic.Bool
	)
	first := newTestMember(C.TypeHysteria2, "first", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if reset.CompareAndSwap(false, true) {
			// as the outbound of a QUIC protocol answers the callers that wait for its
			// connection when it is told of a new interface
			urlTest.InterfaceUpdated()
			return nil, E.New("network changed")
		}
		return dialWorking(ctx, network, destination)
	})
	second := newTestMember(C.TypeVLESS, "second", dialWorking)
	urlTest, group := newTestURLTest(t, link, first, second)
	group.outbound = &testOutboundManager{members: map[string]adapter.Outbound{"first": first, "second": second}}

	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	// the reset forces a round
	require.Eventually(t, func() bool { return requests.Load() >= 2 && !group.checking.Load() }, 5*time.Second, 5*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, "first", group.selectedOutboundTCP.Load().Tag(), "the reset was taken for a failure of the member")
	require.NotNil(t, group.history.LoadURLTestHistory("first"))
}

// A connect that is cancelled while its caller still waits (the one a first write starts
// with tcp_fast_open, ended by a reset of the network) is not the member's failure.
func TestURLTestCancelledConnectIgnored(t *testing.T) {
	link, requests := testURL(t, 0)
	first := newTestMember(C.TypeVLESS, "first", func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: context.Canceled}
	})
	second := newTestMember(C.TypeVLESS, "second", dialWorking)
	urlTest, group := newTestURLTest(t, link, first, second)

	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	time.Sleep(50 * time.Millisecond)
	require.NotNil(t, group.history.LoadURLTestHistory("first"))
	require.Equal(t, "first", group.selectedOutboundTCP.Load().Tag())
	require.Equal(t, int32(0), requests.Load())
}

// The write that carries the connect fails after the network changed under the dial: of
// the network that was, as a failed dial is.
func TestURLTestHandshakeWriteAcrossANetworkChange(t *testing.T) {
	link, _ := testURL(t, 0)
	urlTest, group := newTestURLTest(t, link, newLazyMember(t, syscall.ECONNRESET), newTestMember(C.TypeVLESS, "spare", dialWorking))
	paused := &testPause{}
	group.watchPause(paused)

	conn, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.NoError(t, err)
	paused.set(true)
	paused.set(false)
	writer, _ := N.UnwrapCountWriter(conn, nil) // as kickWriteHandshake does
	_, err = writer.Write([]byte("payload"))
	require.ErrorIs(t, err, syscall.ECONNRESET)
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, "member", group.selectedOutboundTCP.Load().Tag())
}

// A confirming test that was on its way when the network went and came back is of the
// network that was: the result of the member stays.
func TestURLTestConfirmAcrossAShortOutage(t *testing.T) {
	link, _ := testURL(t, 0)
	paused := &testPause{}
	member := newTestMember(C.TypeVLESS, "member", func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		paused.set(true)
		paused.set(false)
		return nil, syscall.ECONNREFUSED
	})
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, member, spare)
	group.watchPause(paused)

	// a failed packet dial is confirmed by a URL test of the member
	_, err := urlTest.ListenPacket(context.Background(), M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	waitConfirmed(t, group, "member")
	require.Equal(t, int32(1), member.dials.Load())
	require.NotNil(t, group.history.LoadURLTestHistory("member"), "a test cut by the outage erased the result")
	require.Equal(t, "member", group.selectedOutboundTCP.Load().Tag())
}

// A confirming test that met the missing route at the beginning of an outage shorter
// than the wait for the monitor: the route is back before the failure is looked at.
func TestURLTestConfirmLocalNetworkErrorAcrossAShortOutage(t *testing.T) {
	shortLocalFailureGrace(t)
	link, _ := testURL(t, 0)
	member := newTestMember(C.TypeVLESS, "member", dialUnreachable)
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, member, spare)
	paused := &testPause{}
	group.watchPause(paused)

	_, err := urlTest.ListenPacket(context.Background(), M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	waitConfirmed(t, group, "member")
	require.Equal(t, int32(1), member.dials.Load())
	time.Sleep(localFailureGrace / 4)
	paused.set(true)
	time.Sleep(localFailureGrace / 4)
	paused.set(false)
	time.Sleep(2 * localFailureGrace)
	require.NotNil(t, group.history.LoadURLTestHistory("member"), "judged after the outage for a failure of its beginning")
	require.Equal(t, "member", group.selectedOutboundTCP.Load().Tag())
	_, waiting := group.localFailures.Load("member")
	require.False(t, waiting, "the failure was not looked at")
}

// A forced round that is asked for as the running one ends, after that one has looked at
// the flag: the request is the only one left to act on it, and one round follows.
func TestURLTestRecheckAskedAsTheRoundEnds(t *testing.T) {
	link, _ := testURL(t, 0)
	member := newTestMember(C.TypeVLESS, "member", dialWorking)
	_, group := newTestURLTest(t, link, member)
	group.outbound = &testOutboundManager{members: map[string]adapter.Outbound{"member": member}}

	group.requestRecheck()
	require.Eventually(t, func() bool { return member.dials.Load() == 1 }, 5*time.Second, 5*time.Millisecond, "no round followed")
	time.Sleep(300 * time.Millisecond)
	require.Equal(t, int32(1), member.dials.Load(), "more than one round followed")
	require.False(t, group.recheck.Load())
}

// Where the monitor never sees a default route the manager stops the ticker of the group
// for good. Once a member has passed a URL test after the report, the group runs its
// rounds again: without them a member that lost its result would never be tested. A
// report that comes after that is believed again, and the rounds stop.
func TestURLTestRoundsWhereMonitorSeesNoRoute(t *testing.T) {
	link, requests := testURL(t, 0)
	member := newTestMember(C.TypeVLESS, "member", dialWorking)
	urlTest, group := newTestURLTest(t, link, member)
	group.outbound = &testOutboundManager{members: map[string]adapter.Outbound{"member": member}}
	paused := &testPause{}
	paused.set(true)
	group.watchPause(paused)
	group.interval = 200 * time.Millisecond
	group.started = true
	group.lastActive.Store(time.Now())
	t.Cleanup(func() { group.Close() })

	// the report is believed: no round, and none to try it either while the member has
	// a result, which the rounds of a real outage would erase
	urlTest.group.Touch()
	time.Sleep(3 * group.interval)
	urlTest.group.Touch()
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, int32(0), requests.Load())

	// the round at start, or a test asked for by hand, passes: the rounds go on
	group.CheckOutbounds(true)
	require.Equal(t, int32(1), requests.Load())
	require.False(t, group.networkPaused())
	require.Eventually(t, func() bool { return requests.Load() >= 4 }, 5*time.Second, 10*time.Millisecond, "no periodic round where the report is refuted")

	// the network is seen, and then goes: that report is believed
	require.Eventually(t, func() bool { return !group.checking.Load() }, 2*time.Second, time.Millisecond)
	paused.set(false)
	paused.set(true)
	require.True(t, group.networkPaused())
	require.Eventually(t, func() bool { return !group.checking.Load() }, 2*time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	tested := requests.Load()
	time.Sleep(3 * group.interval)
	require.Equal(t, tested, requests.Load(), "rounds during a pause that nothing has refuted")
}

// A group is told of a reset of the network before the reset ends the dials in flight.
// The outbounds are told of the new interface one after another, the members before the
// group as a rule, and what their waiting dials say then is the reset's.
func TestURLTestToldOfAResetFirst(t *testing.T) {
	link, requests := testURL(t, 20*time.Millisecond)
	var urlTest *URLTest
	first := newTestMember(C.TypeHysteria2, "first", func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		// the network manager has told the group; this member is told next and ends
		// the dials that wait for its connection
		urlTest.NetworkReset()
		return nil, E.New("network changed")
	})
	second := newTestMember(C.TypeVLESS, "second", dialWorking)
	urlTest, group := newTestURLTest(t, link, first, second)

	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, "first", group.selectedOutboundTCP.Load().Tag(), "the reset was taken for a failure of the member")
	require.NotNil(t, group.history.LoadURLTestHistory("first"))
	require.Equal(t, int32(0), requests.Load())
}

// Where the monitor never sees a default route and sing-box started before the uplink was
// there, the round at start failed: no member has a result, the ticker is stopped, and no
// event comes when the uplink does. The group then runs a round itself, an interval at
// most, while it is in use; the first member that passes refutes the report.
func TestURLTestProbesWhereMonitorSeesNoRoute(t *testing.T) {
	link, requests := testURL(t, 0)
	member := newTestMember(C.TypeVLESS, "member", dialWorking)
	urlTest, group := newTestURLTest(t, link, member)
	group.outbound = &testOutboundManager{members: map[string]adapter.Outbound{"member": member}}
	paused := &testPause{}
	paused.set(true)
	group.watchPause(paused)
	group.interval = 200 * time.Millisecond
	group.started = true
	group.lastActive.Store(time.Now())
	// the round at start has just failed
	group.lastRound.Store(int64(time.Since(group.epoch)))
	group.history.DeleteURLTestHistory("member")
	t.Cleanup(func() { group.Close() })

	urlTest.group.Touch()
	urlTest.group.Touch()
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, int32(0), requests.Load(), "a round sooner than an interval after the last one")
	time.Sleep(group.interval)
	urlTest.group.Touch()
	require.Eventually(t, func() bool { return requests.Load() >= 1 }, 5*time.Second, 5*time.Millisecond, "no round where no member has a result")
	// the member has passed: the report is refuted, and the rounds go on by the ticker
	require.Eventually(t, func() bool { return requests.Load() >= 3 }, 5*time.Second, 10*time.Millisecond)
}

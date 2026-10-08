package group

import (
	"context"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// testPause is a pause manager whose network state the test sets.
type testPause struct {
	pause.Manager
	networkPaused atomic.Bool
}

func (p *testPause) IsDevicePaused() bool  { return false }
func (p *testPause) IsNetworkPaused() bool { return p.networkPaused.Load() }

// Without a default interface every dial fails at once. That is not the members' failure:
// their test results stay, and the group does not walk through them erasing each.
func TestURLTestPausedNetworkKeepsResults(t *testing.T) {
	link, requests := testURL(t, 0)
	first := newTestMember(C.TypeVLESS, "first", dialRefused)
	second := newTestMember(C.TypeVLESS, "second", dialRefused)
	urlTest, group := newTestURLTest(t, link, first, second)
	paused := &testPause{}
	paused.networkPaused.Store(true)
	group.pause = paused

	for range 3 {
		_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
		require.Error(t, err)
	}
	time.Sleep(50 * time.Millisecond)
	require.NotNil(t, group.history.LoadURLTestHistory("first"))
	require.NotNil(t, group.history.LoadURLTestHistory("second"))
	require.Equal(t, "first", group.selectedOutboundTCP.Load().Tag())
	require.Equal(t, int32(0), requests.Load())

	// the network is back: the same failure is the member's again
	paused.networkPaused.Store(false)
	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	waitSelected(t, group, "second")
	require.Nil(t, group.history.LoadURLTestHistory("first"))
}

// A confirming test that fails because the network went away while it ran is discarded.
func TestURLTestConfirmDuringPauseDiscarded(t *testing.T) {
	link, _ := testURL(t, 0)
	paused := &testPause{}
	member := newTestMember(C.TypeVLESS, "member", func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		paused.networkPaused.Store(true) // the interface goes down under the test
		return nil, syscall.ENETUNREACH
	})
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, member, spare)
	group.pause = paused

	// a failed packet dial is confirmed by a URL test of the member
	_, err := urlTest.ListenPacket(context.Background(), M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	waitConfirmed(t, group, "member")
	require.Equal(t, int32(1), member.dials.Load())
	require.NotNil(t, group.history.LoadURLTestHistory("member"), "a test cut by the pause erased the result")
	require.Equal(t, "member", group.selectedOutboundTCP.Load().Tag())
}

// A forced round asked for while another one runs is not lost: one more round follows the
// running one, however many times it was asked for. A new default interface forces a round;
// the one in progress tested the old state.
func TestURLTestForcedRoundFollowsBusyRound(t *testing.T) {
	link, _ := testURL(t, 0)
	release := make(chan struct{})
	var blocked atomic.Bool
	member := newTestMember(C.TypeVLESS, "member", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if blocked.CompareAndSwap(false, true) {
			<-release
		}
		return dialWorking(ctx, network, destination)
	})
	_, group := newTestURLTest(t, link, member)
	group.outbound = &testOutboundManager{members: map[string]adapter.Outbound{"member": member}}

	go group.CheckOutbounds(true)
	require.Eventually(t, func() bool { return member.dials.Load() == 1 }, 2*time.Second, 5*time.Millisecond)
	for range 5 {
		group.CheckOutbounds(true) // returns at once: a round is running
	}
	require.Equal(t, int32(1), member.dials.Load())
	close(release)
	require.Eventually(t, func() bool { return member.dials.Load() == 2 }, 5*time.Second, 5*time.Millisecond, "no round followed the busy one")
	time.Sleep(300 * time.Millisecond)
	require.Equal(t, int32(2), member.dials.Load(), "more than one round followed")
	require.Eventually(t, func() bool { return !group.checking.Load() }, 2*time.Second, 5*time.Millisecond)
}

// A round that is not forced and meets a running one asks for nothing.
func TestURLTestPlainRoundDoesNotQueue(t *testing.T) {
	link, _ := testURL(t, 0)
	release := make(chan struct{})
	var blocked atomic.Bool
	member := newTestMember(C.TypeVLESS, "member", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if blocked.CompareAndSwap(false, true) {
			<-release
		}
		return dialWorking(ctx, network, destination)
	})
	_, group := newTestURLTest(t, link, member)
	group.outbound = &testOutboundManager{members: map[string]adapter.Outbound{"member": member}}

	go group.CheckOutbounds(true)
	require.Eventually(t, func() bool { return member.dials.Load() == 1 }, 2*time.Second, 5*time.Millisecond)
	group.CheckOutbounds(false)
	close(release)
	time.Sleep(300 * time.Millisecond)
	require.Equal(t, int32(1), member.dials.Load())
}

// A member is frozen as of the start of its download test: a URL test that passed while the
// download ran is a newer result, so the next selection tries the member again instead of
// keeping it out until the round after.
func TestURLTestFrozenAsOfDownloadStart(t *testing.T) {
	shortDownloadTimeout(t)
	full := newDownloadServer(t, "full")
	frozen := newDownloadServer(t, "stall")
	var aDead atomic.Bool
	a := newTestMember(C.TypeVLESS, "a", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if aDead.Load() {
			return nil, syscall.ECONNREFUSED
		}
		return dialTo(full)(ctx, network, destination)
	})
	b := newTestMember(C.TypeVLESS, "b", dialTo(frozen))
	c := newTestMember(C.TypeVLESS, "c", dialTo(full))
	urlTest, group := newTestURLTest(t, full.URL, a, b, c)
	group.downloadLink = full.URL

	aDead.Store(true)
	// a URL test of b passes while its download test (300 ms) is running
	go func() {
		require.Eventually(t, func() bool { return frozen.gets.Load() == 1 }, 2*time.Second, time.Millisecond)
		time.Sleep(50 * time.Millisecond)
		group.history.StoreURLTestHistory("b", &adapter.URLTestHistory{Time: time.Now(), Delay: 110})
	}()
	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	waitSelected(t, group, "c")
	require.Equal(t, int32(1), frozen.gets.Load())

	group.performUpdateCheck()
	require.Equal(t, int32(2), frozen.gets.Load(), "the result that came during the download test did not count as newer")
}

// A dial that fails through the group returns one error that names the member, and the
// error still is what it was for the code above the group.
func TestURLTestDialErrorNamesMember(t *testing.T) {
	link, _ := testURL(t, 0)
	blackholed := newTestMember(C.TypeVLESS, "blackholed", func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
	})
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, _ := newTestURLTest(t, link, blackholed, spare)

	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "outbound/vless[blackholed]: ")
	var netErr net.Error
	require.True(t, errors.As(err, &netErr) && netErr.Timeout())
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)

	_, err = urlTest.ListenPacket(context.Background(), M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "outbound/vless[")
	require.ErrorIs(t, err, os.ErrInvalid)
}

// dialUnreachable fails as a dial does when this host has no route to the server.
func dialUnreachable(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}
}

func shortLocalFailureGrace(t *testing.T) {
	saved := localFailureGrace
	localFailureGrace = 300 * time.Millisecond
	t.Cleanup(func() { localFailureGrace = saved })
}

// The route goes a second before the network monitor reports that there is no default
// interface, and the dials of that second fail with "network is unreachable". They are
// this host's failure: once the monitor has spoken the members still have their test
// results, and the group has not moved.
func TestURLTestLocalNetworkErrorWaitsForMonitor(t *testing.T) {
	shortLocalFailureGrace(t)
	link, requests := testURL(t, 0)
	first := newTestMember(C.TypeVLESS, "first", dialUnreachable)
	second := newTestMember(C.TypeVLESS, "second", dialUnreachable)
	urlTest, group := newTestURLTest(t, link, first, second)
	paused := &testPause{}
	group.pause = paused

	for range 3 {
		_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
		require.Error(t, err)
	}
	paused.networkPaused.Store(true) // the monitor speaks
	time.Sleep(2 * localFailureGrace)
	require.NotNil(t, group.history.LoadURLTestHistory("first"))
	require.NotNil(t, group.history.LoadURLTestHistory("second"))
	require.Equal(t, "first", group.selectedOutboundTCP.Load().Tag())
	require.Equal(t, int32(3), first.dials.Load())
	require.Equal(t, int32(0), second.dials.Load())
	require.Equal(t, int32(0), requests.Load())
}

// With the network still there after that time the missing route was the member's own (an
// interface it is bound to went down): the member is unavailable, as after any failed dial.
func TestURLTestLocalNetworkErrorOfOneMember(t *testing.T) {
	shortLocalFailureGrace(t)
	link, _ := testURL(t, 0)
	first := newTestMember(C.TypeVLESS, "first", dialUnreachable)
	second := newTestMember(C.TypeVLESS, "second", dialWorking)
	urlTest, group := newTestURLTest(t, link, first, second)
	group.pause = &testPause{}

	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	require.NotNil(t, group.history.LoadURLTestHistory("first"), "judged before the monitor could speak")
	waitSelected(t, group, "second")
	require.Nil(t, group.history.LoadURLTestHistory("first"))
}

// A member tested after the failure, by the round a new default interface forces, keeps
// that result: the failure was of the network that is no more.
func TestURLTestLocalNetworkErrorOutdated(t *testing.T) {
	shortLocalFailureGrace(t)
	link, _ := testURL(t, 0)
	first := newTestMember(C.TypeVLESS, "first", dialUnreachable)
	second := newTestMember(C.TypeVLESS, "second", dialWorking)
	urlTest, group := newTestURLTest(t, link, first, second)
	group.pause = &testPause{}

	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	group.history.StoreURLTestHistory("first", &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	time.Sleep(2 * localFailureGrace)
	require.NotNil(t, group.history.LoadURLTestHistory("first"))
	require.Equal(t, "first", group.selectedOutboundTCP.Load().Tag())
}

// A confirming test that met the missing route waits for the monitor too.
func TestURLTestConfirmLocalNetworkErrorWaitsForMonitor(t *testing.T) {
	shortLocalFailureGrace(t)
	link, _ := testURL(t, 0)
	member := newTestMember(C.TypeVLESS, "member", dialUnreachable)
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, member, spare)
	paused := &testPause{}
	group.pause = paused

	// a failed packet dial is confirmed by a URL test of the member, which finds no route
	_, err := urlTest.ListenPacket(context.Background(), M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	waitConfirmed(t, group, "member")
	require.Equal(t, int32(1), member.dials.Load())
	paused.networkPaused.Store(true)
	time.Sleep(2 * localFailureGrace)
	require.NotNil(t, group.history.LoadURLTestHistory("member"))
	require.Equal(t, "member", group.selectedOutboundTCP.Load().Tag())

	// and without the monitor's word the member is unavailable after that time
	paused.networkPaused.Store(false)
	allowConfirm(group, "member", time.Now())
	_, err = urlTest.ListenPacket(context.Background(), M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	waitSelected(t, group, "spare")
	require.Nil(t, group.history.LoadURLTestHistory("member"))
}

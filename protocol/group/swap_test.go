package group

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

// newSwapGroup makes a group of the members on a shared history, as the groups of one box
// have it.
func newSwapGroup(t *testing.T, history *urltest.HistoryStorage, link string, members ...adapter.Outbound) *URLTest {
	ctx := service.ContextWith[pause.Manager](service.ContextWithPtr(context.Background(), history), &testPause{})
	group, err := NewURLTestGroup(ctx, nil, log.NewNOPFactory().Logger(), members, nil, link, "", time.Minute, 50, 0, false)
	require.NoError(t, err)
	t.Cleanup(func() { group.Close() })
	return &URLTest{group: group, logger: log.NewNOPFactory().NewLogger("urltest")}
}

// The group that takes the tag keeps the choice of the one before when it has the same
// member, the members it froze of those, and tests only the members without a result.
func TestURLTestTakeOver(t *testing.T) {
	link, _ := testURL(t, 0)
	history := urltest.NewHistoryStorage()
	a := newTestMember(C.TypeVLESS, "a", dialWorking)
	b := newTestMember(C.TypeVLESS, "b", dialWorking)
	history.StoreURLTestHistory("a", &adapter.URLTestHistory{Time: time.Now(), Delay: 300})
	history.StoreURLTestHistory("b", &adapter.URLTestHistory{Time: time.Now(), Delay: 280})
	old := newSwapGroup(t, history, link, a, b)
	old.group.performUpdateCheck()
	require.Equal(t, "a", old.group.selectedOutboundTCP.Load().Tag())
	old.group.setFrozen("a", time.Now())
	old.group.setFrozen("b", time.Now())

	// b is another object under its tag now, c is new and faster than a by far once tested
	b2 := newTestMember(C.TypeVLESS, "b", dialWorking)
	c := newTestMember(C.TypeVLESS, "c", dialWorking)
	next := newSwapGroup(t, history, link, a, b2, c)
	next.TakeOver(old)
	require.Same(t, adapter.Outbound(a), next.group.selectedOutboundTCP.Load())
	require.Same(t, adapter.Outbound(a), next.group.selectedOutboundUDP.Load())
	require.Contains(t, next.group.frozen.Load(), "a")
	require.NotContains(t, next.group.frozen.Load(), "b", "b is another server now")

	history.DeleteURLTestHistory("b") // as the backend forgets the result of a changed server
	next.group.PostStart()
	require.Eventually(t, func() bool {
		return history.LoadURLTestHistory("c") != nil && history.LoadURLTestHistory("b") != nil
	}, 5*time.Second, 10*time.Millisecond)
	require.Zero(t, a.dials.Load(), "a has a result: not tested")
	require.NotZero(t, b2.dials.Load())

	// a group of another type, or one not started, is no source
	other := newSwapGroup(t, urltest.NewHistoryStorage(), link, c)
	other.TakeOver(&Selector{})
	require.Nil(t, other.group.selectedOutboundTCP.Load())
	require.False(t, other.group.hotStart)
}

// The first round of a group that took over tests the members without a result a few at a
// time.
func TestURLTestTakeOverRoundIsGentle(t *testing.T) {
	var running, most atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := running.Add(1)
		defer running.Add(-1)
		for {
			seen := most.Load()
			if now <= seen || most.CompareAndSwap(seen, now) {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	history := urltest.NewHistoryStorage()
	var outbounds []adapter.Outbound
	for _, tag := range []string{"m1", "m2", "m3", "m4", "m5", "m6", "m7"} {
		outbounds = append(outbounds, newTestMember(C.TypeVLESS, tag, dialWorking))
	}
	old := newSwapGroup(t, history, server.URL, outbounds[0])
	next := newSwapGroup(t, history, server.URL, outbounds...)
	next.TakeOver(old)
	next.group.PostStart()
	require.Eventually(t, func() bool {
		for _, member := range outbounds {
			if history.LoadURLTestHistory(member.Tag()) == nil {
				return false
			}
		}
		return true
	}, 10*time.Second, 10*time.Millisecond)
	require.Equal(t, int32(hotRoundConcurrency), most.Load())
}

// A group that was replaced tests, chooses and judges no more, and its rounds in progress
// leave no result.
func TestURLTestRetire(t *testing.T) {
	link, requests := testURL(t, 200*time.Millisecond)
	history := urltest.NewHistoryStorage()
	a := newTestMember(C.TypeVLESS, "a", dialWorking)
	group := newSwapGroup(t, history, link, a)
	group.group.PostStart()
	group.group.Touch()
	require.Eventually(t, func() bool { return requests.Load() > 0 }, 2*time.Second, 5*time.Millisecond)

	group.Retire()
	require.NoError(t, group.group.Close(), "a second close does nothing")
	group.group.Touch()
	group.group.access.Lock()
	ticker := group.group.ticker
	group.group.access.Unlock()
	require.Nil(t, ticker, "no ticker after the close")
	time.Sleep(400 * time.Millisecond)
	require.Nil(t, history.LoadURLTestHistory("a"), "the round in progress wrote nothing")

	_, err := group.URLTest(context.Background())
	require.Error(t, err)
	group.group.CheckOutbounds(context.Background(), true)
	before := requests.Load()
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, before, requests.Load(), "no round")

	history.StoreURLTestHistory("a", &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	group.group.memberFailed(context.Background(), a, N.NetworkTCP, net.ErrClosed, time.Now())
	group.group.memberFailed(context.Background(), a, N.NetworkTCP, &net.OpError{Op: "dial", Err: errRefusedForTest}, time.Now())
	require.NotNil(t, history.LoadURLTestHistory("a"), "a failure judges nothing")
	require.False(t, group.group.updatePending.Load())
}

var errRefusedForTest = &net.AddrError{Err: "refused", Addr: "test"}

// The connections the group dialed count for their member while they are open, whether the
// group closes them (Interrupt) or their user does.
func TestURLTestMembersInUse(t *testing.T) {
	link, _ := testURL(t, 0)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()
	history := urltest.NewHistoryStorage()
	a := newTestMember(C.TypeVLESS, "a", dialWorking)
	b := newTestMember(C.TypeVLESS, "b", dialWorking)
	history.StoreURLTestHistory("a", &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	history.StoreURLTestHistory("b", &adapter.URLTestHistory{Time: time.Now(), Delay: 500})
	group := newSwapGroup(t, history, link, a, b)
	group.group.performUpdateCheck()
	destination := M.ParseSocksaddr(listener.Addr().String())

	first, err := group.DialContext(context.Background(), N.NetworkTCP, destination)
	require.NoError(t, err)
	second, err := group.DialContext(context.Background(), N.NetworkTCP, destination)
	require.NoError(t, err)
	require.Equal(t, []adapter.Outbound{a}, group.MembersInUse())
	require.NoError(t, first.Close())
	first.Close() // a second close counts once
	require.Equal(t, []adapter.Outbound{a}, group.MembersInUse())

	// the group closes what it dialed when it switches: the user closes its end after
	group.group.interruptGroup.Interrupt(true)
	require.Equal(t, []adapter.Outbound{a}, group.MembersInUse())
	second.Close()
	require.Empty(t, group.MembersInUse())

	// what the group dials past its choice while that waits counts for the member it dialed
	history.DeleteURLTestHistory("a")
	group.group.downloadLink = "http://127.0.0.1:1/"
	third, err := group.DialContext(context.Background(), N.NetworkTCP, destination)
	require.NoError(t, err)
	t.Cleanup(func() { third.Close() })
	require.Equal(t, []adapter.Outbound{b}, group.MembersInUse())
	require.Equal(t, "a", group.group.selectedOutboundTCP.Load().Tag(), "the chain names a")
}

// A group that was replaced lets go of its members but those it chose; a selector of all but
// the one it chose.
func TestReleaseMembers(t *testing.T) {
	link, _ := testURL(t, 0)
	history := urltest.NewHistoryStorage()
	a := newTestMember(C.TypeVLESS, "a", dialWorking)
	b := newTestMember(C.TypeVLESS, "b", dialWorking)
	history.StoreURLTestHistory("a", &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	group := newSwapGroup(t, history, link, a, b)
	group.group.performUpdateCheck()
	group.Retire()
	group.ReleaseMembers()
	require.Nil(t, group.group.members)
	require.Nil(t, group.group.outbounds)
	require.Same(t, adapter.Outbound(a), group.group.selectedOutboundTCP.Load())
	require.Same(t, adapter.Outbound(a), group.Selected(N.NetworkTCP))

	selector := &Selector{outbounds: map[string]adapter.Outbound{"a": a, "b": b}, tags: []string{"a", "b"}, interruptGroup: interrupt.NewGroup()}
	selector.selected.Store(a)
	selector.ReleaseMembers()
	require.Empty(t, selector.outbounds)
	require.False(t, selector.SelectOutbound("b"))
	require.Same(t, adapter.Outbound(a), selector.Selected(N.NetworkTCP))
}

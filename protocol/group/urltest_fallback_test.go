package group

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// newTestFallbackGroup makes a group of the outbounds and the fallbacks, gives the members
// in delays their test results and selects, with the download test at downloadLink.
func newTestFallbackGroup(t *testing.T, link, downloadLink string, outbounds, fallbacks []adapter.Outbound, delays map[string]uint16) (*URLTest, *URLTestGroup) {
	history := urltest.NewHistoryStorage()
	ctx := service.ContextWithPtr(context.Background(), history)
	manager := &testOutboundManager{members: make(map[string]adapter.Outbound)}
	for _, member := range append(append([]adapter.Outbound{}, outbounds...), fallbacks...) {
		manager.members[member.Tag()] = member
	}
	for tag, delay := range delays {
		history.StoreURLTestHistory(tag, &adapter.URLTestHistory{Time: time.Now(), Delay: delay})
	}
	group, err := NewURLTestGroup(ctx, manager, log.NewNOPFactory().Logger(), outbounds, fallbacks, link, downloadLink, time.Minute, 50, 0, false)
	require.NoError(t, err)
	group.performUpdateCheck()
	return &URLTest{group: group, logger: log.NewNOPFactory().NewLogger("urltest")}, group
}

// setResult gives the member a new test result, or takes it away (delay 0).
func setResult(group *URLTestGroup, tag string, delay uint16) {
	if delay == 0 {
		group.history.DeleteURLTestHistory(tag)
		return
	}
	group.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{Time: time.Now(), Delay: delay})
}

func members(members ...*testMember) []adapter.Outbound {
	outbounds := make([]adapter.Outbound, len(members))
	for i, member := range members {
		outbounds[i] = member
	}
	return outbounds
}

func selectedTags(group *URLTestGroup) (string, string) {
	return group.selectedOutboundTCP.Load().Tag(), group.selectedOutboundUDP.Load().Tag()
}

// While an outbound answers, no fallback is chosen, a faster one neither, for TCP or UDP.
func TestURLTestFallbackUnusedWhileOutboundsAnswer(t *testing.T) {
	link, _ := testURL(t, 0)
	a := newTestMember(C.TypeVLESS, "a", dialWorking)
	b := newTestMember(C.TypeVLESS, "b", dialWorking)
	f := newTestMember(C.TypeSOCKS, "f", dialWorking)
	_, group := newTestFallbackGroup(t, link, "", members(a, b), members(f), map[string]uint16{"a": 400, "b": 300, "f": 10})
	tcp, udp := selectedTags(group)
	require.Equal(t, "b", tcp)
	require.Equal(t, "b", udp)

	setResult(group, "b", 0)
	group.performUpdateCheck()
	tcp, udp = selectedTags(group)
	require.Equal(t, "a", tcp)
	require.Equal(t, "a", udp)
}

// Without an outbound that answers, the first fallback that does is chosen: the order of
// the list, not the delay; an earlier fallback that answers again is taken back.
func TestURLTestFallbackOrder(t *testing.T) {
	link, _ := testURL(t, 0)
	a := newTestMember(C.TypeVLESS, "a", dialRefused)
	f1 := newTestMember(C.TypeSOCKS, "f1", dialWorking)
	f2 := newTestMember(C.TypeSOCKS, "f2", dialWorking)
	_, group := newTestFallbackGroup(t, link, "", members(a), members(f1, f2), map[string]uint16{"f1": 500, "f2": 10})
	tcp, udp := selectedTags(group)
	require.Equal(t, "f1", tcp)
	require.Equal(t, "f1", udp)

	setResult(group, "f1", 0)
	group.performUpdateCheck()
	tcp, udp = selectedTags(group)
	require.Equal(t, "f2", tcp)
	require.Equal(t, "f2", udp)

	setResult(group, "f1", 500)
	group.performUpdateCheck()
	tcp, udp = selectedTags(group)
	require.Equal(t, "f1", tcp)
	require.Equal(t, "f1", udp)
}

// An outbound that answers again replaces the fallback in use, also one slower than the
// fallback, or within the tolerance of it.
func TestURLTestFallbackReturnsToOutbound(t *testing.T) {
	link, _ := testURL(t, 0)
	for _, delay := range []uint16{120, 900} {
		a := newTestMember(C.TypeVLESS, "a", dialWorking)
		f := newTestMember(C.TypeSOCKS, "f", dialWorking)
		_, group := newTestFallbackGroup(t, link, "", members(a), members(f), map[string]uint16{"f": 100})
		require.Equal(t, "f", group.selectedOutboundTCP.Load().Tag())

		setResult(group, "a", delay)
		group.performUpdateCheck()
		tcp, udp := selectedTags(group)
		require.Equal(t, "a", tcp, "delay %d", delay)
		require.Equal(t, "a", udp, "delay %d", delay)
	}
}

// With the download test, a frozen fallback is passed over for the next one, and is not
// tested again without a new result; an outbound that answers again passes the test and
// replaces the fallback.
func TestURLTestFallbackDownloadCheck(t *testing.T) {
	shortDownloadTimeout(t)
	full := newDownloadServer(t, "full")
	frozen := newDownloadServer(t, "stall")
	a := newTestMember(C.TypeVLESS, "a", dialTo(full))
	f1 := newTestMember(C.TypeSOCKS, "f1", dialTo(frozen))
	f2 := newTestMember(C.TypeSOCKS, "f2", dialTo(full))
	_, group := newTestFallbackGroup(t, full.URL, full.URL, members(a), members(f1, f2), map[string]uint16{"f1": 10, "f2": 20})
	tcp, udp := selectedTags(group)
	require.Equal(t, "f2", tcp)
	require.Equal(t, "f2", udp)
	require.Equal(t, int32(1), frozen.gets.Load())
	require.Equal(t, int32(1), full.gets.Load())

	group.performUpdateCheck()
	require.Equal(t, int32(1), frozen.gets.Load(), "tested again without a new test result")
	require.Equal(t, int32(1), full.gets.Load(), "the fallback in use was tested again")
	require.Equal(t, "f2", group.selectedOutboundTCP.Load().Tag())

	setResult(group, "a", 300)
	group.performUpdateCheck()
	require.Equal(t, int32(2), full.gets.Load())
	tcp, udp = selectedTags(group)
	require.Equal(t, "a", tcp)
	require.Equal(t, "a", udp)
}

// A frozen outbound, taken as the last resort while no fallback answered, gives way to a
// fallback that passes the download test; the outbound's next result, once it has
// recovered, brings it back.
func TestURLTestFallbackReplacesFrozenOutbound(t *testing.T) {
	shortDownloadTimeout(t)
	full := newDownloadServer(t, "full")
	frozen := newDownloadServer(t, "stall")
	a := newTestMember(C.TypeVLESS, "a", dialTo(frozen))
	f := newTestMember(C.TypeSOCKS, "f", dialTo(full))
	_, group := newTestFallbackGroup(t, full.URL, full.URL, members(a), members(f), map[string]uint16{"a": 10})
	require.Equal(t, "a", group.selectedOutboundTCP.Load().Tag(), "a frozen member is better than none")
	require.Equal(t, int32(1), frozen.gets.Load())

	setResult(group, "f", 100)
	group.performUpdateCheck()
	require.Equal(t, "f", group.selectedOutboundTCP.Load().Tag())
	require.Equal(t, int32(1), frozen.gets.Load())
	require.Equal(t, int32(1), full.gets.Load())

	frozen.mode.Store("full")
	setResult(group, "a", 10)
	group.performUpdateCheck()
	require.Equal(t, int32(2), frozen.gets.Load())
	require.Equal(t, "a", group.selectedOutboundTCP.Load().Tag())
}

// With no member answering, the selection stays; a dial without a selection takes the
// plain choice, the first outbound.
func TestURLTestFallbackAllDown(t *testing.T) {
	link, _ := testURL(t, 0)
	a := newTestMember(C.TypeVLESS, "a", dialWorking)
	f := newTestMember(C.TypeSOCKS, "f", dialWorking)
	_, group := newTestFallbackGroup(t, link, "", members(a), members(f), map[string]uint16{"f": 10})
	require.Equal(t, "f", group.selectedOutboundTCP.Load().Tag())

	setResult(group, "f", 0)
	group.performUpdateCheck()
	require.Equal(t, "f", group.selectedOutboundTCP.Load().Tag())

	urlTest, group := newTestFallbackGroup(t, link, "", members(a), members(f), nil)
	require.Equal(t, "a", group.selectedOutboundTCP.Load().Tag())
	conn, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr(link[len("http://"):]))
	require.NoError(t, err)
	conn.Close()
	require.Equal(t, int32(1), a.dials.Load())
	require.Equal(t, int32(0), f.dials.Load())
}

// While the selected outbound has lost its result and the selection waits for a download
// test, connections go through the fallback that answers.
func TestURLTestFallbackWhileSelectionPending(t *testing.T) {
	link, _ := testURL(t, 0)
	a := newTestMember(C.TypeVLESS, "a", dialRefused)
	f := newTestMember(C.TypeSOCKS, "f", dialWorking)
	urlTest, group := newTestFallbackGroup(t, link, "", members(a), members(f), map[string]uint16{"a": 10, "f": 100})
	require.Equal(t, "a", group.selectedOutboundTCP.Load().Tag())
	group.downloadLink = link
	setResult(group, "a", 0)
	group.updateAccess.Lock() // the selection is busy
	defer group.updateAccess.Unlock()

	conn, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr(link[len("http://"):]))
	require.NoError(t, err)
	conn.Close()
	require.Equal(t, int32(0), a.dials.Load())
	require.Equal(t, int32(1), f.dials.Load())
}

// Each round tests the fallbacks with the outbounds.
func TestURLTestFallbackTestedEachRound(t *testing.T) {
	link, requests := testURL(t, 0)
	a := newTestMember(C.TypeVLESS, "a", dialWorking)
	f1 := newTestMember(C.TypeSOCKS, "f1", dialWorking)
	f2 := newTestMember(C.TypeSOCKS, "f2", dialWorking)
	_, group := newTestFallbackGroup(t, link, "", members(a), members(f1, f2), nil)

	result, err := group.urlTest(context.Background(), true)
	require.NoError(t, err)
	require.Len(t, result, 3)
	require.Equal(t, int32(3), requests.Load())
	require.Equal(t, "a", group.selectedOutboundTCP.Load().Tag())
}

// A failed dial through the fallback in use (S1) moves the group to the next fallback.
func TestURLTestFallbackFailureSwitches(t *testing.T) {
	link, _ := testURL(t, 0)
	a := newTestMember(C.TypeVLESS, "a", dialRefused)
	f1 := newTestMember(C.TypeVLESS, "f1", dialRefused)
	f2 := newTestMember(C.TypeVLESS, "f2", dialWorking)
	urlTest, group := newTestFallbackGroup(t, link, "", members(a), members(f1, f2), map[string]uint16{"f1": 10, "f2": 10})
	require.Equal(t, "f1", group.selectedOutboundTCP.Load().Tag())

	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	waitSelected(t, group, "f2")
	require.Nil(t, group.history.LoadURLTestHistory("f1"))
}

// An outbound declared down by a failed dial (S1) gives way to the fallback, and gets its
// connections without an answer closed.
func TestURLTestFallbackClosesUnanswered(t *testing.T) {
	t.Parallel()
	link, _ := testURL(t, 0)
	server := newFakeServer(link)
	var refuse atomic.Bool
	a := newTestMember(C.TypeVLESS, "a", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if refuse.Load() {
			return nil, syscall.ECONNREFUSED
		}
		return server.dial(ctx, network, destination)
	})
	f := newTestMember(C.TypeSOCKS, "f", dialWorking)
	urlTest, group := newTestFallbackGroup(t, link, "", members(a), members(f), map[string]uint16{"a": 10, "f": 10})
	require.Equal(t, "a", group.selectedOutboundTCP.Load().Tag())

	preconnect, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("preconnect.example:443"))
	require.NoError(t, err)
	defer preconnect.Close()
	_, done := readAll(preconnect)

	refuse.Store(true)
	_, err = urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	require.Error(t, err)
	waitSelectedWithin(t, group, "f", 2*time.Second)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the preconnect of the outbound declared down was not closed")
	}
}

// testGroup is a group member that is a group itself, with the member now in use.
type testGroup struct {
	*testMember
	member adapter.Outbound
}

func (g *testGroup) All() []string                              { return []string{g.member.Tag()} }
func (g *testGroup) Selected(string) adapter.Outbound           { return g.member }
func (g *testGroup) AttachConnection(io.Closer) (detach func()) { return func() {} }

// A fallback that is a group is judged by the member it uses, and tested through it.
func TestURLTestFallbackNestedGroup(t *testing.T) {
	link, requests := testURL(t, 0)
	a := newTestMember(C.TypeVLESS, "a", dialRefused)
	inner := newTestMember(C.TypeSOCKS, "inner", dialWorking)
	selector := &testGroup{testMember: newTestMember(C.TypeSelector, "selector", inner.dial), member: inner}
	_, group := newTestFallbackGroup(t, link, "", members(a), []adapter.Outbound{selector}, map[string]uint16{"inner": 10})
	group.outbound.(*testOutboundManager).members["inner"] = inner
	group.performUpdateCheck()
	require.Equal(t, "selector", group.selectedOutboundTCP.Load().Tag())

	setResult(group, "inner", 0)
	_, err := group.urlTest(context.Background(), true)
	require.NoError(t, err)
	require.Equal(t, int32(1), inner.dials.Load())
	require.Equal(t, int32(1), requests.Load())
	require.NotNil(t, group.history.LoadURLTestHistory("inner"))
}

// The options: All and the dependencies list the outbounds, then the fallbacks; a tag
// listed twice is an error.
func TestURLTestFallbackOptions(t *testing.T) {
	newGroup := func(outbounds, fallbacks []string) (*URLTest, error) {
		created, err := NewURLTest(context.Background(), nil, log.NewNOPFactory().NewLogger("urltest"), "auto", option.URLTestOutboundOptions{
			Outbounds: outbounds,
			Fallbacks: fallbacks,
		})
		if err != nil {
			return nil, err
		}
		return created.(*URLTest), nil
	}
	outbounds := make([]string, 2, 8) // room to grow: the options must not be written into
	copy(outbounds, []string{"a", "b"})
	urlTest, err := newGroup(outbounds, []string{"f1", "f2"})
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b", "f1", "f2"}, urlTest.All())
	require.Equal(t, []string{"a", "b", "f1", "f2"}, urlTest.Dependencies())
	require.Equal(t, []string{"a", "b"}, outbounds)
	require.Equal(t, []string{"a", "b", "", ""}, outbounds[:4])

	urlTest, err = newGroup([]string{"a", "b"}, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, urlTest.All())
	require.Equal(t, []string{"a", "b"}, urlTest.Dependencies())

	_, err = newGroup([]string{"a", "b"}, []string{"b"})
	require.Error(t, err)
	_, err = newGroup([]string{"a"}, []string{"f", "f"})
	require.Error(t, err)
	// fallbacks alone make a group (podkop-engine r20); nothing at all does not
	urlTest, err = newGroup(nil, []string{"f"})
	require.NoError(t, err)
	require.Equal(t, []string{"f"}, urlTest.All())
	_, err = newGroup(nil, nil)
	require.Error(t, err)
	// sing-box 1.14.4 refuses a tag listed twice in the outbounds too
	_, err = newGroup([]string{"a", "a"}, nil)
	require.Error(t, err)
}

// Start resolves the fallbacks; a missing one is an error.
func TestURLTestFallbackStart(t *testing.T) {
	a := newTestMember(C.TypeVLESS, "a", dialWorking)
	f := newTestMember(C.TypeSOCKS, "f", dialWorking)
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	ctx = service.ContextWith[adapter.OutboundManager](ctx, &testOutboundManager{members: map[string]adapter.Outbound{"a": a, "f": f}})
	for _, testCase := range []struct {
		fallbacks []string
		err       bool
	}{
		{[]string{"f"}, false},
		{[]string{"f", "missing"}, true},
	} {
		created, err := NewURLTest(ctx, nil, log.NewNOPFactory().NewLogger("urltest"), "auto", option.URLTestOutboundOptions{
			Outbounds: []string{"a"},
			Fallbacks: testCase.fallbacks,
		})
		require.NoError(t, err)
		urlTest := created.(*URLTest)
		if testCase.err {
			require.Error(t, startURLTest(t, urlTest))
			continue
		}
		require.NoError(t, startURLTest(t, urlTest))
		require.Equal(t, []adapter.Outbound{a}, urlTest.group.outbounds)
		require.Equal(t, []adapter.Outbound{f}, urlTest.group.fallbacks)
		require.Equal(t, []adapter.Outbound{a, f}, urlTest.group.members)
	}
}

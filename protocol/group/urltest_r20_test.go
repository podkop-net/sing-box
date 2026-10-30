package group

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
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

// A URL test without outbounds takes its fallbacks: what is left of a rule whose provider
// took every server away. With neither it is refused.
func TestURLTestOfFallbacksOnly(t *testing.T) {
	t.Parallel()
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	_, err := NewURLTest(ctx, nil, log.NewNOPFactory().NewLogger("urltest"), "t", option.URLTestOutboundOptions{Fallbacks: []string{"f1"}})
	require.NoError(t, err)
	_, err = NewURLTest(ctx, nil, log.NewNOPFactory().NewLogger("urltest"), "t", option.URLTestOutboundOptions{})
	require.ErrorContains(t, err, "missing tags")

	f1, f2 := newTestMember(C.TypeSOCKS, "f1", dialRefused), newTestMember(C.TypeSOCKS, "f2", dialRefused)
	_, group := newTestFallbackGroup(t, "", "", nil, members(f1, f2), map[string]uint16{"f2": 100})
	tcp, udp := selectedTags(group)
	require.Equal(t, "f2", tcp)
	require.Equal(t, "f2", udp)
	setResult(group, "f2", 0)
	group.performUpdateCheck()
	tcp, _ = selectedTags(group)
	require.Equal(t, "f2", tcp, "none answers: the one in use stays")
}

// A block fallback answers by refusing: chosen when nothing before it answers, never judged
// failed for its refusals, given up as soon as a server answers again.
func TestBlockFallbackAnswers(t *testing.T) {
	t.Parallel()
	server, dead := newTestMember(C.TypeSOCKS, "a", dialRefused), newTestMember(C.TypeSOCKS, "dead", dialRefused)
	block := newTestMember(C.TypeBlock, "block", dialRefused)
	_, group := newTestFallbackGroup(t, "", "", members(server), members(dead, block), map[string]uint16{"a": 100})
	tcp, _ := selectedTags(group)
	require.Equal(t, "a", tcp)
	setResult(group, "a", 0)
	group.performUpdateCheck()
	tcp, udp := selectedTags(group)
	require.Equal(t, "block", tcp)
	require.Equal(t, "block", udp)
	group.memberFailed(context.Background(), block, N.NetworkTCP, errors.New("refused"), time.Now())
	tcp, _ = selectedTags(group)
	require.Equal(t, "block", tcp, "a refusal of block is no failure")
	setResult(group, "a", 120)
	group.performUpdateCheck()
	tcp, _ = selectedTags(group)
	require.Equal(t, "a", tcp)
}

// No more URL tests than probeSlots run at once in the process. Not parallel: the slots are
// those of the whole process.
func TestProbeLimit(t *testing.T) {
	var now, most atomic.Int32
	release := make(chan struct{})
	slow := newTestMember(C.TypeSOCKS, "slow", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		running := now.Add(1)
		defer now.Add(-1)
		for {
			seen := most.Load()
			if running <= seen || most.CompareAndSwap(seen, running) {
				break
			}
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, errors.New("down")
	})
	var done sync.WaitGroup
	for range 3 * cap(probeSlots) {
		done.Add(1)
		go func() {
			defer done.Done()
			_, _ = testOutbound(context.Background(), "http://www.example.com/generate_204", slow)
		}()
	}
	require.Eventually(t, func() bool { return now.Load() == int32(cap(probeSlots)) }, 5*time.Second, 10*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, int32(cap(probeSlots)), most.Load())
	close(release)
	done.Wait()
	require.Equal(t, int32(cap(probeSlots)), most.Load())
	require.Equal(t, int32(3*cap(probeSlots)), slow.dials.Load())
}

// Before a round has tested the members a fallback is not taken for want of their results: at
// a start or after a swap a block fallback would refuse every connection.
func TestNoFallbackBeforeARound(t *testing.T) {
	t.Parallel()
	history := urltest.NewHistoryStorage()
	ctx := service.ContextWithPtr(context.Background(), history)
	server, block := newTestMember(C.TypeSOCKS, "a", dialRefused), newTestMember(C.TypeBlock, "block", dialRefused)
	manager := &testOutboundManager{members: map[string]adapter.Outbound{"a": server, "block": block}}
	group, err := NewURLTestGroup(ctx, manager, log.NewNOPFactory().Logger(), members(server), members(block), "", "", time.Minute, 50, 0, false)
	require.NoError(t, err)
	selected, found := group.Select(N.NetworkTCP)
	require.Equal(t, "a", selected.Tag())
	require.False(t, found)
	group.roundDone.Store(true)
	selected, found = group.Select(N.NetworkTCP)
	require.Equal(t, "block", selected.Tag(), "tested and not answering: the fallback")
	require.True(t, found)
}

// Before a round a group of fallbacks alone takes its first fallback, not a block further
// down: a rule whose servers are gone and whose fallbacks are direct, then block.
func TestFallbacksOnlyBeforeARound(t *testing.T) {
	t.Parallel()
	history := urltest.NewHistoryStorage()
	ctx := service.ContextWithPtr(context.Background(), history)
	direct, block := newTestMember(C.TypeDirect, "direct", dialRefused), newTestMember(C.TypeBlock, "block", dialRefused)
	manager := &testOutboundManager{members: map[string]adapter.Outbound{"direct": direct, "block": block}}
	group, err := NewURLTestGroup(ctx, manager, log.NewNOPFactory().Logger(), nil, members(direct, block), "", "", time.Minute, 50, 0, false)
	require.NoError(t, err)
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		selected, found := group.Select(network)
		require.Equal(t, "direct", selected.Tag(), network)
		require.False(t, found)
	}
	group.roundDone.Store(true)
	selected, found := group.Select(N.NetworkTCP)
	require.Equal(t, "block", selected.Tag(), "tested, direct did not answer: block")
	require.True(t, found)
}

// The first round of a group that took over, when every member has a result already, tests
// nothing and still counts as a round: a member that fails after it gives way to a fallback.
func TestTakeOverWithResultsIsARound(t *testing.T) {
	t.Parallel()
	a, f := newTestMember(C.TypeSOCKS, "a", dialRefused), newTestMember(C.TypeSOCKS, "f", dialRefused)
	_, group := newTestFallbackGroup(t, "", "", members(a), members(f), map[string]uint16{"a": 100, "f": 200})
	group.roundDone.Store(false)
	group.checkUntested()
	require.True(t, group.roundDone.Load())
	require.Zero(t, a.dials.Load()+f.dials.Load(), "nothing to test")
	setResult(group, "a", 0)
	group.performUpdateCheck()
	tcp, _ := selectedTags(group)
	require.Equal(t, "f", tcp)
}

// A block fallback is taken without a download test: it downloads nothing.
func TestBlockFallbackWithoutDownloadTest(t *testing.T) {
	t.Parallel()
	a, block := newTestMember(C.TypeSOCKS, "a", dialRefused), newTestMember(C.TypeBlock, "block", dialRefused)
	_, group := newTestFallbackGroup(t, "", "http://www.example.com/64k", members(a), members(block), nil)
	tcp, _ := selectedTags(group)
	require.Equal(t, "block", tcp)
	require.Zero(t, block.dials.Load())
}

// While a block fallback is the choice, rounds come sooner than the interval, so the servers
// come back soon after the network that failed them. Not parallel: blockRetryFirst is the
// package's.
func TestBlockFallbackRetried(t *testing.T) {
	first := blockRetryFirst
	blockRetryFirst = 50 * time.Millisecond
	t.Cleanup(func() { blockRetryFirst = first })
	link, _ := testURL(t, 0)
	var up atomic.Bool
	a := newTestMember(C.TypeSOCKS, "a", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if !up.Load() {
			return nil, errors.New("down")
		}
		return dialWorking(ctx, network, destination)
	})
	block := newTestMember(C.TypeBlock, "block", dialRefused)
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	manager := &testOutboundManager{members: map[string]adapter.Outbound{"a": a, "block": block}}
	group, err := NewURLTestGroup(ctx, manager, log.NewNOPFactory().Logger(), members(a), members(block), link, "", 10*time.Minute, 50, 0, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = group.Close() })
	group.lastActive.Store(time.Now())
	group.CheckOutbounds(ctx, true)
	tcp, _ := selectedTags(group)
	require.Equal(t, "block", tcp)
	require.Eventually(t, func() bool { return a.dials.Load() >= 3 }, 5*time.Second, 10*time.Millisecond, "rounds while block is chosen")
	up.Store(true)
	require.Eventually(t, func() bool {
		tcp, _ := selectedTags(group)
		return tcp == "a"
	}, 5*time.Second, 10*time.Millisecond)
	group.updateAccess.Lock()
	armed := group.blockRetryTimer != nil
	group.updateAccess.Unlock()
	require.False(t, armed, "no more rounds once a server answers")
}

// A confirming test of a failing member does not wait for probeSlots: behind the rounds it
// would keep the group on a dead member. Not parallel: the slots are those of the process.
func TestConfirmPastProbeSlots(t *testing.T) {
	for range cap(probeSlots) {
		probeSlots <- struct{}{}
	}
	t.Cleanup(func() {
		for range cap(probeSlots) {
			<-probeSlots
		}
	})
	a, f := newTestMember(C.TypeSOCKS, "a", dialRefused), newTestMember(C.TypeSOCKS, "f", dialRefused)
	_, group := newTestFallbackGroup(t, "http://www.example.com/generate_204", "", members(a), members(f), map[string]uint16{"a": 100, "f": 200})
	require.True(t, group.confirmFailure("a", a))
	require.Eventually(t, func() bool { return a.dials.Load() > 0 }, 5*time.Second, 10*time.Millisecond)
}

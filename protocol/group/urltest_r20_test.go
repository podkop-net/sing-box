package group

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

package outbound_test

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type swapOutbound struct {
	outbound.Adapter
}

func newSwapOutbound(tag string) *swapOutbound {
	return &swapOutbound{Adapter: outbound.NewAdapter("test", tag, []string{N.NetworkTCP}, nil)}
}

func (o *swapOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, os.ErrInvalid
}

func (o *swapOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func tagsOf(outbounds []adapter.Outbound) []string {
	tags := make([]string, len(outbounds))
	for i, outbound := range outbounds {
		tags[i] = outbound.Tag()
	}
	return tags
}

// newSwapManager is a manager of the outbounds of the tags, the first the default.
func newSwapManager(t *testing.T, tags ...string) *outbound.Manager {
	registry := outbound.NewRegistry()
	outbound.Register[struct{}](registry, "test", func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options struct{}) (adapter.Outbound, error) {
		return newSwapOutbound(tag), nil
	})
	manager := outbound.NewManager(registry, endpoint.NewManager(nil), "")
	for _, tag := range tags {
		require.NoError(t, manager.Create(context.Background(), nil, nil, tag, "test", &struct{}{}))
	}
	return manager
}

// An outbound takes the place of the one of its tag, a new tag goes after the others, and
// a removed one is gone; who read the list before keeps it as it was.
func TestSwapOutbounds(t *testing.T) {
	manager := newSwapManager(t, "a", "b", "c")
	before := manager.Outbounds()
	oldB, _ := manager.Outbound("b")
	oldC, _ := manager.Outbound("c")
	newB, d := newSwapOutbound("b"), newSwapOutbound("d")

	previous, err := manager.SwapOutbounds([]adapter.Outbound{d, newB}, []string{"c"})
	require.NoError(t, err)
	require.ElementsMatch(t, []adapter.Outbound{oldB, oldC}, previous)
	require.Equal(t, []string{"a", "b", "d"}, tagsOf(manager.Outbounds()))
	found, loaded := manager.Outbound("b")
	require.True(t, loaded)
	require.Same(t, adapter.Outbound(newB), found)
	_, loaded = manager.Outbound("c")
	require.False(t, loaded)
	require.Equal(t, []string{"a", "b", "c"}, tagsOf(before))
	require.Same(t, oldB, before[1])

	// the default outbound is replaced, never removed
	newA := newSwapOutbound("a")
	_, err = manager.SwapOutbounds([]adapter.Outbound{newA}, nil)
	require.NoError(t, err)
	require.Same(t, adapter.Outbound(newA), manager.Default())
	_, err = manager.SwapOutbounds(nil, []string{"a"})
	require.ErrorContains(t, err, "default outbound")

	// what cannot be done changes nothing
	for _, testCase := range []struct {
		put    []adapter.Outbound
		remove []string
	}{
		{[]adapter.Outbound{newSwapOutbound("e"), newSwapOutbound("e")}, nil},
		{[]adapter.Outbound{newSwapOutbound("b")}, []string{"b"}},
		{nil, []string{"missing"}},
		{nil, []string{"d", "d"}},
	} {
		listed := manager.Outbounds()
		_, err = manager.SwapOutbounds(testCase.put, testCase.remove)
		require.Error(t, err)
		require.Equal(t, listed, manager.Outbounds())
	}
}

// NewOutbound builds what Create would, and puts nothing in the manager.
func TestNewOutbound(t *testing.T) {
	manager := newSwapManager(t, "a")
	created, err := manager.NewOutbound(context.Background(), nil, nil, "a", "test", &struct{}{})
	require.NoError(t, err)
	require.Equal(t, "a", created.Tag())
	found, _ := manager.Outbound("a")
	require.NotSame(t, created, found)
	_, err = manager.NewOutbound(context.Background(), nil, nil, "", "test", &struct{}{})
	require.Error(t, err)
}

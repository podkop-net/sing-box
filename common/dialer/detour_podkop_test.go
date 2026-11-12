package dialer

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

type namedOutbound struct {
	adapter.Outbound
	name string
}

func (o *namedOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, os.ErrInvalid
}

type swappingManager struct {
	adapter.OutboundManager
	byTag    map[string]adapter.Outbound
	fallback adapter.Outbound
}

func (m *swappingManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.byTag[tag]
	return outbound, loaded
}

func (m *swappingManager) Default() adapter.Outbound {
	return m.fallback
}

// A detour dials through the outbound its tag has now: one replaced while the box runs is followed.
func TestDetourFollowsTheTag(t *testing.T) {
	first, second := &namedOutbound{name: "first"}, &namedOutbound{name: "second"}
	manager := &swappingManager{byTag: map[string]adapter.Outbound{"proxy": first}, fallback: first}
	detour := NewDetour(manager, "proxy", true).(*DetourDialer)
	current, err := detour.Dialer()
	require.NoError(t, err)
	require.Same(t, first, current)
	manager.byTag["proxy"] = second
	current, err = detour.Dialer()
	require.NoError(t, err)
	require.Same(t, second, current, "the outbound of the tag now")
	delete(manager.byTag, "proxy")
	current, _ = detour.Dialer()
	require.Same(t, first, current, "while the tag has none, the one found first")

	byDefault := NewDefaultOutboundDetour(manager).(*DetourDialer)
	current, _ = byDefault.Dialer()
	require.Same(t, first, current)
	manager.fallback = second
	current, _ = byDefault.Dialer()
	require.Same(t, second, current)

	missing := NewDetour(&swappingManager{byTag: map[string]adapter.Outbound{}}, "nothing", true).(*DetourDialer)
	_, err = missing.Dialer()
	require.ErrorContains(t, err, "outbound detour not found")
}

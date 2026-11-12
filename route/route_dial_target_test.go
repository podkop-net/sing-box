package route

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type fakeSelector struct{ fakeGroup }

type fakeURLTest struct{ fakeGroup }

func (fakeURLTest) URLTest(context.Context) (map[string]uint16, error) { return nil, nil }
func (fakeURLTest) PerformUpdateCheck()                                {}

// A routed connection of a chain with a URL test is dialed through the URL test, which judges
// the dials of its members; other chains through their last outbound, as sing-box dials them.
func TestDialTarget(t *testing.T) {
	member := fakeOutbound{typ: "vless"}
	urltest := fakeURLTest{fakeGroup{fakeOutbound{typ: "urltest"}, member}}
	selector := fakeSelector{fakeGroup{fakeOutbound{typ: "selector"}, urltest}}
	var _ adapter.URLTestGroup = urltest

	chain, err := resolveOutbound(selector, N.NetworkTCP)
	require.NoError(t, err)
	require.Equal(t, []adapter.Outbound{selector, urltest, member}, chain)
	require.Equal(t, adapter.Outbound(urltest), dialTarget(chain))

	// a member chosen by hand in the selector
	selector = fakeSelector{fakeGroup{fakeOutbound{typ: "selector"}, member}}
	chain, err = resolveOutbound(selector, N.NetworkUDP)
	require.NoError(t, err)
	require.Equal(t, adapter.Outbound(member), dialTarget(chain))
	require.Equal(t, adapter.Outbound(member), dialTarget([]adapter.Outbound{member}))
}

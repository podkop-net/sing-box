package route

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	E "github.com/sagernet/sing/common/exceptions"
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

type countingURLTest struct {
	fakeGroup
	checks *int
}

func (countingURLTest) URLTest(context.Context) (map[string]uint16, error) { return nil, nil }
func (g countingURLTest) PerformUpdateCheck()                              { *g.checks++ }

// A failed dial of a chain with a URL test is the group's to judge (it was dialed through it):
// sing-box 1.14.5 takes the result of the last outbound of the chain away and asks each URL test of
// the chain to select again, here the history stays as it is and no group is asked.
func TestFailedDialLeftToTheURLTest(t *testing.T) {
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory("vless", &adapter.URLTestHistory{Time: time.Now(), Delay: 100})
	checks := 0
	member := fakeOutbound{typ: "vless"}
	group := countingURLTest{fakeGroup{fakeOutbound{typ: "urltest"}, member}, &checks}
	var _ adapter.URLTestGroup = group
	manager := &ConnectionManager{urlTestHistory: history}
	manager.deleteURLTestHistory([]adapter.Outbound{group, member}, E.New("connection refused"))
	require.NotNil(t, history.LoadURLTestHistory("vless"))
	require.Zero(t, checks)
}

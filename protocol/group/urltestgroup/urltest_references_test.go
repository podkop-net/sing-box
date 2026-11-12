package urltestgroup

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// outboundReferences are the outbounds the group references (adapter.Referrer); it names no DNS
// server.
func outboundReferences(t *testing.T, urlTest *URLTest) []string {
	t.Helper()
	var referrer adapter.Referrer = urlTest
	outbounds, dnsServers := referrer.References()
	require.Empty(t, dnsServers)
	return outbounds
}

// The group references what it dials through: the choice of each network, a fallback when it is
// the choice. Its dependencies, from which the box orders the start and checks a configuration,
// are all the outbounds and fallbacks.
func TestReferencesFollowTheChoice(t *testing.T) {
	link, _ := testURL(t, 0)
	a := newTestMember(C.TypeVLESS, "a", dialWorking)
	b := newTestMember(C.TypeVLESS, "b", dialWorking)
	tcpOnly := &testMember{Adapter: outbound.NewAdapter(C.TypeVLESS, "tcp", []string{N.NetworkTCP}, nil), dial: dialWorking}
	f := newTestMember(C.TypeSOCKS, "f", dialWorking)
	urlTest, group := newTestFallbackGroup(t, link, "", members(a, b, tcpOnly), members(f), map[string]uint16{"a": 400, "b": 300, "f": 10})
	require.Equal(t, []string{"b"}, outboundReferences(t, urlTest))

	// the fastest for TCP carries no UDP: both are referenced
	setResult(group, "tcp", 100)
	group.performUpdateCheck()
	require.Equal(t, []string{"tcp", "b"}, outboundReferences(t, urlTest))

	// no outbound answers: the fallback is the choice
	for _, tag := range []string{"a", "b", "tcp"} {
		setResult(group, tag, 0)
	}
	group.performUpdateCheck()
	require.Equal(t, []string{"f"}, outboundReferences(t, urlTest))

	setResult(group, "a", 200)
	group.performUpdateCheck()
	require.Equal(t, []string{"a"}, outboundReferences(t, urlTest))

	// before its start a group references nothing, as upstream's
	require.Empty(t, outboundReferences(t, &URLTest{}))

	created, err := NewURLTest(context.Background(), nil, log.NewNOPFactory().NewLogger("urltest"), "g", option.URLTestOutboundOptions{
		Outbounds: []string{"a", "b"},
		Fallbacks: []string{"f"},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b", "f"}, created.Dependencies())
	created, err = NewURLTest(context.Background(), nil, log.NewNOPFactory().NewLogger("urltest"), "g", option.URLTestOutboundOptions{
		Fallbacks: []string{"f", "block"},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"f", "block"}, created.Dependencies())
}

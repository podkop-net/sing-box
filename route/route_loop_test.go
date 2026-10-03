package route

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

type fakeOutbound struct {
	adapter.Outbound
	typ string
}

func (o fakeOutbound) Type() string { return o.typ }

type fakeListenInbound struct {
	adapter.Inbound
	addr M.Socksaddr
}

func (i fakeListenInbound) ListenAddress() M.Socksaddr { return i.addr }

type fakeGroup struct {
	fakeOutbound
	now string
}

func (g fakeGroup) Now() string   { return g.now }
func (g fakeGroup) All() []string { return []string{g.now} }

type fakeOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m fakeOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	out, ok := m.outbounds[tag]
	return out, ok
}

type fakeInboundManager struct {
	adapter.InboundManager
	inbounds map[string]adapter.Inbound
}

func (m fakeInboundManager) Get(tag string) (adapter.Inbound, bool) {
	in, ok := m.inbounds[tag]
	return in, ok
}

// The loop guard must fire exactly on a connection a direct outbound would dial back to the
// same inbound it arrived on, and never on legitimate chaining to another local inbound.
func TestWouldLoopToInbound(t *testing.T) {
	t.Parallel()
	dnsIn := M.ParseSocksaddr("127.0.0.42:53")
	tproxyIn := M.ParseSocksaddr("127.0.0.1:1602")
	mixedIn := M.ParseSocksaddr("127.0.0.1:17001")
	r := &Router{inbound: fakeInboundManager{inbounds: map[string]adapter.Inbound{
		"dns-in":    fakeListenInbound{addr: dnsIn},
		"tproxy-in": fakeListenInbound{addr: tproxyIn},
		"mixed-in":  fakeListenInbound{addr: mixedIn},
	}}}
	direct := fakeOutbound{typ: C.TypeDirect}
	socks := fakeOutbound{typ: C.TypeSOCKS}
	mk := func(inbound string, dest M.Socksaddr) *adapter.InboundContext {
		return &adapter.InboundContext{Inbound: inbound, Destination: dest}
	}

	// the loop: a datagram on dns-in that was not hijacked is dialled by the direct outbound
	// back to dns-in's own address
	require.True(t, r.wouldLoopToInbound(mk("dns-in", dnsIn), direct))

	// legitimate chaining: a connection on tproxy-in routed through a urltest/selector to a
	// socks outbound that points at a local mixed inbound. The outbound is socks, not direct.
	require.False(t, r.wouldLoopToInbound(mk("tproxy-in", mixedIn), socks))

	// even a direct outbound to a DIFFERENT inbound's address is left alone
	require.False(t, r.wouldLoopToInbound(mk("tproxy-in", dnsIn), direct))

	// a direct outbound to the same inbound but a different port is not the loop
	require.False(t, r.wouldLoopToInbound(mk("dns-in", M.ParseSocksaddr("127.0.0.42:80")), direct))

	// a socks outbound to the same inbound address is allowed: only the direct outbound dials
	// the raw destination that forms the loop
	require.False(t, r.wouldLoopToInbound(mk("dns-in", dnsIn), socks))

	// an unknown inbound tag (no listener) is not treated as a loop
	require.False(t, r.wouldLoopToInbound(mk("gone", dnsIn), direct))
}

// A group dials through its selected member: a selector or urltest whose current member is
// the direct outbound forms the same loop; one whose member is a proxy does not.
func TestWouldLoopToInboundThroughGroup(t *testing.T) {
	t.Parallel()
	dnsIn := M.ParseSocksaddr("127.0.0.42:53")
	direct := fakeOutbound{typ: C.TypeDirect}
	socks := fakeOutbound{typ: C.TypeSOCKS}
	r := &Router{
		inbound: fakeInboundManager{inbounds: map[string]adapter.Inbound{"dns-in": fakeListenInbound{addr: dnsIn}}},
		outbound: fakeOutboundManager{outbounds: map[string]adapter.Outbound{
			"direct":    direct,
			"socks":     socks,
			"to-direct": fakeGroup{fakeOutbound{typ: C.TypeSelector}, "direct"},
		}},
	}
	metadata := &adapter.InboundContext{Inbound: "dns-in", Destination: dnsIn}
	require.True(t, r.wouldLoopToInbound(metadata, fakeGroup{fakeOutbound{typ: C.TypeURLTest}, "direct"}))
	require.True(t, r.wouldLoopToInbound(metadata, fakeGroup{fakeOutbound{typ: C.TypeSelector}, "to-direct"}), "a group inside a group")
	require.False(t, r.wouldLoopToInbound(metadata, fakeGroup{fakeOutbound{typ: C.TypeURLTest}, "socks"}))
	require.False(t, r.wouldLoopToInbound(metadata, fakeGroup{fakeOutbound{typ: C.TypeURLTest}, "missing"}), "a member that is gone")
}

// A listener on every address (0.0.0.0, ::) is reached at whichever address the connection
// came in on: that address, with the listen port, is the loop; another port, or another
// host's address, is not.
func TestWouldLoopToInboundWildcard(t *testing.T) {
	t.Parallel()
	direct := fakeOutbound{typ: C.TypeDirect}
	r := &Router{inbound: fakeInboundManager{inbounds: map[string]adapter.Inbound{
		"any4": fakeListenInbound{addr: M.ParseSocksaddr("0.0.0.0:53")},
		"any6": fakeListenInbound{addr: M.ParseSocksaddr("[::]:53")},
	}}}
	accepted := M.ParseSocksaddr("192.168.1.1:53")
	// TCP: the destination is the original one, the address the connection was accepted on
	require.True(t, r.wouldLoopToInbound(&adapter.InboundContext{Inbound: "any4", Destination: accepted, OriginDestination: accepted}, direct))
	require.True(t, r.wouldLoopToInbound(&adapter.InboundContext{Inbound: "any6", Destination: accepted, OriginDestination: accepted}, direct))
	// UDP: the destination is the bind address itself
	require.True(t, r.wouldLoopToInbound(&adapter.InboundContext{Inbound: "any4", Destination: M.ParseSocksaddr("0.0.0.0:53")}, direct))
	// an override to another host, or to another port, is no loop
	require.False(t, r.wouldLoopToInbound(&adapter.InboundContext{Inbound: "any4", Destination: M.ParseSocksaddr("8.8.8.8:53"), OriginDestination: accepted}, direct))
	require.False(t, r.wouldLoopToInbound(&adapter.InboundContext{Inbound: "any4", Destination: M.ParseSocksaddr("192.168.1.1:5353"), OriginDestination: accepted}, direct))
}

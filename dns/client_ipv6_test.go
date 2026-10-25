package dns

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// ipv6TestTransport answers from a table of names: a name it has no address of the type
// for gets a success without records, a name not in the table NXDOMAIN. It counts the
// questions it was asked by type.
type ipv6TestTransport struct {
	tag           string
	transportType string
	records       map[string]map[uint16][]netip.Addr

	access  sync.Mutex
	queries map[uint16]int
}

func newIPv6TestTransport(tag string, transportType string) *ipv6TestTransport {
	return &ipv6TestTransport{
		tag: tag, transportType: transportType, queries: make(map[uint16]int),
		records: map[string]map[uint16][]netip.Addr{
			"v6only.test.": {mDNS.TypeAAAA: {netip.MustParseAddr("2001:db8::1")}},
			"dual.test.":   {mDNS.TypeA: {netip.MustParseAddr("192.0.2.2")}, mDNS.TypeAAAA: {netip.MustParseAddr("2001:db8::2")}},
		},
	}
}

func (t *ipv6TestTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}
func (t *ipv6TestTransport) Type() string           { return t.transportType }
func (t *ipv6TestTransport) Tag() string            { return t.tag }
func (t *ipv6TestTransport) Dependencies() []string { return nil }
func (t *ipv6TestTransport) Reset()                 {}

func (t *ipv6TestTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	question := message.Question[0]
	t.access.Lock()
	t.queries[question.Qtype]++
	t.access.Unlock()
	types, known := t.records[question.Name]
	if !known {
		return FixedResponseStatus(message, mDNS.RcodeNameError), nil
	}
	return FixedResponse(message.Id, question, types[question.Qtype], 300), nil
}

func (t *ipv6TestTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		callback(t.Exchange(ctx, message))
	}()
}

func (t *ipv6TestTransport) asked(qType uint16) int {
	t.access.Lock()
	defer t.access.Unlock()
	return t.queries[qType]
}

func ipv6TestClient(enabled bool) *Client {
	return NewClient(ClientOptions{
		Context:      context.Background(),
		Logger:       log.NewNOPFactory().Logger(),
		IPv6IfNoIPv4: enabled,
	})
}

func ipv6TestQuestion(name string, qType uint16) *mDNS.Msg {
	message := new(mDNS.Msg)
	message.SetQuestion(name, qType)
	return message
}

func answerAddresses(response *mDNS.Msg) []netip.Addr {
	if response == nil {
		return nil
	}
	return MessageToAddresses(response)
}

var ipv4Only = adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only}

// With ipv4_only and the option an AAAA question goes out for a name without an IPv4
// address; a name with one, a name that does not exist, and every name without the option
// or through a FakeIP server keep the empty answer of the strategy.
func TestIPv6IfNoIPv4Exchange(t *testing.T) {
	ctx := context.Background()
	transport := newIPv6TestTransport("server", C.DNSTypeUDP)
	client := ipv6TestClient(true)

	response, err := client.Exchange(ctx, transport, ipv6TestQuestion("v6only.test.", mDNS.TypeAAAA), ipv4Only, nil)
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8::1")}, answerAddresses(response))
	require.Equal(t, 1, transport.asked(mDNS.TypeA))
	require.Equal(t, 1, transport.asked(mDNS.TypeAAAA))

	// the client asks A and AAAA: the A answer in the cache serves the AAAA question too
	response, err = client.Exchange(ctx, transport, ipv6TestQuestion("dual.test.", mDNS.TypeA), ipv4Only, nil)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.2")}, answerAddresses(response))
	response, err = client.Exchange(ctx, transport, ipv6TestQuestion("dual.test.", mDNS.TypeAAAA), ipv4Only, nil)
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
	require.Empty(t, response.Answer)
	require.Equal(t, 2, transport.asked(mDNS.TypeA), "the A answer of dual.test was not taken from the cache")
	require.Equal(t, 1, transport.asked(mDNS.TypeAAAA))

	response, err = client.Exchange(ctx, transport, ipv6TestQuestion("missing.test.", mDNS.TypeAAAA), ipv4Only, nil)
	require.NoError(t, err)
	require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
	require.Empty(t, response.Answer)
	require.Equal(t, 1, transport.asked(mDNS.TypeAAAA))

	// without the option nothing is asked
	plain := newIPv6TestTransport("server", C.DNSTypeUDP)
	response, err = ipv6TestClient(false).Exchange(ctx, plain, ipv6TestQuestion("v6only.test.", mDNS.TypeAAAA), ipv4Only, nil)
	require.NoError(t, err)
	require.Empty(t, response.Answer)
	require.Zero(t, plain.asked(mDNS.TypeA)+plain.asked(mDNS.TypeAAAA))

	// a FakeIP server is not asked for A
	fakeIP := newIPv6TestTransport("fakeip", C.DNSTypeFakeIP)
	response, err = client.Exchange(ctx, fakeIP, ipv6TestQuestion("v6only.test.", mDNS.TypeAAAA), ipv4Only, nil)
	require.NoError(t, err)
	require.Empty(t, response.Answer)
	require.Zero(t, fakeIP.asked(mDNS.TypeA)+fakeIP.asked(mDNS.TypeAAAA))

	// another strategy: AAAA goes out as ever, without an A question
	other := newIPv6TestTransport("server", C.DNSTypeUDP)
	response, err = client.Exchange(ctx, other, ipv6TestQuestion("dual.test.", mDNS.TypeAAAA), adapter.DNSQueryOptions{Strategy: C.DomainStrategyPreferIPv4}, nil)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8::2")}, answerAddresses(response))
	require.Zero(t, other.asked(mDNS.TypeA))
}

// The asynchronous exchange, which the DNS inbound uses, answers the same.
func TestIPv6IfNoIPv4ExchangeAsync(t *testing.T) {
	transport := newIPv6TestTransport("server", C.DNSTypeUDP)
	client := ipv6TestClient(true)
	exchange := func(name string) *mDNS.Msg {
		done := make(chan *mDNS.Msg, 1)
		client.ExchangeAsync(context.Background(), transport, ipv6TestQuestion(name, mDNS.TypeAAAA), ipv4Only, nil, func(response *mDNS.Msg, err error) {
			require.NoError(t, err)
			done <- response
		})
		return <-done
	}
	require.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8::1")}, answerAddresses(exchange("v6only.test.")))
	response := exchange("dual.test.")
	require.Equal(t, mDNS.RcodeSuccess, response.Rcode)
	require.Empty(t, response.Answer)
	require.Equal(t, 1, transport.asked(mDNS.TypeAAAA))
}

// A lookup with ipv4_only takes the IPv6 addresses of a name without an IPv4 address,
// through the client and through the rules of the router.
func TestIPv6IfNoIPv4Lookup(t *testing.T) {
	ctx := context.Background()
	transport := newIPv6TestTransport("final", C.DNSTypeUDP)
	client := ipv6TestClient(true)
	addresses, err := client.Lookup(ctx, transport, "v6only.test", ipv4Only, nil)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8::1")}, addresses)
	addresses, err = client.Lookup(ctx, transport, "dual.test", ipv4Only, nil)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.2")}, addresses)
	_, err = client.Lookup(ctx, transport, "missing.test", ipv4Only, nil)
	require.Error(t, err)
	addresses, err = ipv6TestClient(false).Lookup(ctx, transport, "v6only.test", ipv4Only, nil)
	require.NoError(t, err)
	require.Empty(t, addresses)

	for _, enabled := range []bool{true, false} {
		router := &Router{
			ctx:       context.Background(),
			logger:    log.NewNOPFactory().Logger(),
			transport: &fakeDNSTransportManager{transports: map[string]adapter.DNSTransport{"final": transport}, defaultTransport: transport},
			client:    ipv6TestClient(enabled),
			// the strategy of the configuration
			defaultDomainStrategy: C.DomainStrategyIPv4Only,
			ipv6IfNoIPv4:          enabled,
		}
		addresses, err = router.lookupWithRules(ctx, nil, "v6only.test", adapter.DNSQueryOptions{})
		require.NoError(t, err)
		if enabled {
			require.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8::1")}, addresses)
		} else {
			require.Empty(t, addresses)
		}
		addresses, err = router.lookupWithRules(ctx, nil, "dual.test", adapter.DNSQueryOptions{})
		require.NoError(t, err)
		require.Equal(t, []netip.Addr{netip.MustParseAddr("192.0.2.2")}, addresses)
	}
}

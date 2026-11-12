package dns

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type groupTestHandler func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error)

// groupTestMember is a member of a group whose exchanges are answered by a function of the
// test.
type groupTestMember struct {
	TransportAdapter
	access  sync.Mutex
	handler groupTestHandler
	calls   int
}

func newGroupTestMember(tag string, handler groupTestHandler) *groupTestMember {
	return &groupTestMember{TransportAdapter: TransportAdapter{transportType: "test", transportTag: tag}, handler: handler}
}

func (m *groupTestMember) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (m *groupTestMember) Reset()                                         {}

func (m *groupTestMember) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	m.access.Lock()
	m.calls++
	handler := m.handler
	m.access.Unlock()
	return handler(ctx, message)
}

func (m *groupTestMember) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		callback(m.Exchange(ctx, message))
	}()
}

func (m *groupTestMember) serve(handler groupTestHandler) {
	m.access.Lock()
	m.handler = handler
	m.access.Unlock()
}

func (m *groupTestMember) asked() int {
	m.access.Lock()
	defer m.access.Unlock()
	return m.calls
}

// groupTestAnswer answers 10.0.0.n after delay.
func groupTestAnswer(n byte, delay time.Duration) groupTestHandler {
	return func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return FixedResponse(message.Id, message.Question[0], []netip.Addr{netip.AddrFrom4([4]byte{10, 0, 0, n})}, 300), nil
	}
}

// groupTestSilent is a server that never answers.
func groupTestSilent(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func groupTestRcode(rcode int) groupTestHandler {
	return func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		return FixedResponseStatus(message, rcode), nil
	}
}

// groupTestWho names who answered: the address, the rcode, or "error".
func groupTestWho(response *mDNS.Msg, err error) string {
	if err != nil {
		return "error"
	}
	if response.Rcode != mDNS.RcodeSuccess {
		return mDNS.RcodeToString[response.Rcode]
	}
	if len(response.Answer) == 1 {
		if record, isA := response.Answer[0].(*mDNS.A); isA {
			return record.A.String()
		}
	}
	return response.String()
}

// The times of the tests: an attempt of a member not measured is cut after 300 ms.
var groupTestTiming = groupTiming{
	attemptMin: 50 * time.Millisecond,
	attemptMax: 300 * time.Millisecond,
	probeFirst: 150 * time.Millisecond,
	probeMax:   600 * time.Millisecond,
	staleAfter: 200 * time.Millisecond,
}

func groupTestLogger(t *testing.T) (logger log.ContextLogger, output *lockedBuffer) {
	t.Helper()
	output = new(lockedBuffer)
	// a real logger, at the debug level: it panics on argument types it does not format
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now(), DisableColors: true}, output, "", nil, false)
	factory.SetLevel(log.LevelDebug)
	if err := factory.Start(); err != nil {
		t.Fatal(err)
	}
	return factory.NewLogger("dns/group[dns-server]"), output
}

func (b *lockedBuffer) has(text string) bool {
	b.access.Lock()
	defer b.access.Unlock()
	return strings.Contains(b.buffer.String(), text)
}

func (b *lockedBuffer) String() string {
	b.access.Lock()
	defer b.access.Unlock()
	return b.buffer.String()
}

// newGroupTest returns the group dns-server of the members, found and with the times of
// the tests; ctx carries the provider's servers of the safety net (groupTestProviders).
func newGroupTest(t *testing.T, ctx context.Context, strategy string, netEnabled bool, members ...adapter.DNSTransport) (*GroupTransport, *lockedBuffer) {
	t.Helper()
	logger, output := groupTestLogger(t)
	transports := make(map[string]adapter.DNSTransport)
	var tags []string
	for _, member := range members {
		tags = append(tags, member.Tag())
		transports[member.Tag()] = member
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if netEnabled {
		// as in a box with the fallback enabled, where each remote member has its state:
		// public unless the test chose otherwise
		for _, member := range members {
			if testMember, isTest := member.(*groupTestMember); isTest && testMember.fallback == nil && testMember.transportType == "test" {
				testMember.fallback = groupTestState("77.88.8.8")
			}
		}
	}
	group, err := newGroupTransport(ctx, logger, "dns-server", option.GroupDNSServerOptions{Servers: tags, Strategy: strategy}, netEnabled)
	require.NoError(t, err)
	group.timing = groupTestTiming
	require.NoError(t, group.resolveMembers(&fakeDNSTransportManager{transports: transports}))
	t.Cleanup(func() { group.close() })
	return group, output
}

// groupTestState is the fallback state of a member whose server is at address.
func groupTestState(address string) *fallbackServer {
	return &fallbackServer{options: option.RemoteDNSServerOptions{DNSServerAddressOptions: option.DNSServerAddressOptions{Server: address}}}
}

// groupTestProviders is the context of a box whose provider's servers are known already.
func groupTestProviders(servers ...M.Socksaddr) context.Context {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegister[*providerSet](ctx, &providerSet{
		read: func(ctx context.Context) ([]netifdInterface, error) {
			return nil, E.New("no ubus in tests")
		},
		servers: servers,
		readAt:  time.Now(),
	})
	return ctx
}

func groupTestQuery(group *GroupTransport) (string, time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	startAt := time.Now()
	response, err := group.Exchange(ctx, freshTestQuery())
	return groupTestWho(response, err), time.Since(startAt)
}

func (g *GroupTransport) testMember(tag string) adapter.DNSGroupMemberState {
	for _, member := range g.GroupState().Members {
		if member.Tag == tag {
			return member
		}
	}
	return adapter.DNSGroupMemberState{}
}

func groupTestExpect(t *testing.T, group *GroupTransport, want string) time.Duration {
	t.Helper()
	got, elapsed := groupTestQuery(group)
	if got != want {
		t.Fatalf("answered by %s, want %s", got, want)
	}
	return elapsed
}

// Bad lists are refused when the group is created, members that do not fit when it finds
// them (the configuration check).
func TestGroupValidation(t *testing.T) {
	t.Parallel()
	logger, _ := groupTestLogger(t)
	for _, test := range []struct {
		options option.GroupDNSServerOptions
		message string
	}{
		{option.GroupDNSServerOptions{}, "missing servers of group dns-server"},
		{option.GroupDNSServerOptions{Servers: []string{"a", ""}}, "empty server tag in group dns-server"},
		{option.GroupDNSServerOptions{Servers: []string{"a", "dns-server"}}, "group dns-server lists itself"},
		{option.GroupDNSServerOptions{Servers: []string{"a", "b", "a"}}, "duplicate server a in group dns-server"},
		{option.GroupDNSServerOptions{Servers: []string{"a"}, Strategy: "random"}, "unknown strategy of group dns-server: random"},
	} {
		_, err := newGroupTransport(context.Background(), logger, "dns-server", test.options, false)
		require.EqualError(t, err, test.message)
	}
	group, err := newGroupTransport(context.Background(), logger, "dns-server", option.GroupDNSServerOptions{Servers: []string{"a", "b"}}, false)
	require.NoError(t, err)
	require.Equal(t, C.DNSGroupStrategyOrder, group.strategy)
	require.Equal(t, []string{"a", "b"}, group.Dependencies()) // they start first
	require.Nil(t, fallbackFor(group), "the group has a fallback of its own")

	member := func(tag string, transportType string) adapter.DNSTransport {
		transport := newGroupTestMember(tag, groupTestAnswer(1, 0))
		transport.transportType = transportType
		return transport
	}
	transports := map[string]adapter.DNSTransport{
		"a":      member("a", C.DNSTypeUDP),
		"g":      member("g", C.DNSTypeGroup),
		"fake":   member("fake", C.DNSTypeFakeIP),
		"hosts":  member("hosts", C.DNSTypeHosts),
		"isp":    member("isp", C.DNSTypeProvider),
		"local":  member("local", C.DNSTypeLocal),
		"tunnel": member("tunnel", C.DNSTypeHTTPS),
	}
	for _, test := range []struct {
		servers []string
		message string
	}{
		{[]string{"a", "missing"}, "server missing of group dns-server not found"},
		{[]string{"a", "g"}, "server g of group dns-server is a group: groups do not nest"},
		{[]string{"fake"}, "server fake of group dns-server is of the type fakeip, which cannot be in a group"},
		{[]string{"a", "hosts"}, "server hosts of group dns-server is of the type hosts, which cannot be in a group"},
		{[]string{"a", "isp", "local", "tunnel"}, ""},
	} {
		group, err := newGroupTransport(context.Background(), logger, "dns-server", option.GroupDNSServerOptions{Servers: test.servers}, false)
		require.NoError(t, err)
		err = group.resolveMembers(&fakeDNSTransportManager{transports: transports})
		if test.message == "" {
			require.NoError(t, err)
			require.Len(t, group.GroupState().Members, len(test.servers))
		} else {
			require.EqualError(t, err, test.message)
		}
	}
}

// The options of both types are parsed with the registry of the box.
func TestGroupOptionsJSON(t *testing.T) {
	t.Parallel()
	registry := NewTransportRegistry()
	RegisterGroupTransport(registry)
	RegisterProviderTransport(registry)
	ctx := service.ContextWith[option.DNSTransportOptionsRegistry](context.Background(), registry)
	var servers []option.DNSServerOptions
	err := json.UnmarshalContext(ctx, []byte(`[
		{"type": "group", "tag": "dns-server", "servers": ["dns-server-1", "dns-server-2"], "strategy": "fastest"},
		{"type": "provider", "tag": "dns-server-2"}
	]`), &servers)
	require.NoError(t, err)
	groupOptions := servers[0].Options.(*option.GroupDNSServerOptions)
	require.Equal(t, []string{"dns-server-1", "dns-server-2"}, []string(groupOptions.Servers))
	require.Equal(t, C.DNSGroupStrategyFastest, groupOptions.Strategy)
	require.IsType(t, &option.ProviderDNSServerOptions{}, servers[1].Options)
	logger, _ := groupTestLogger(t)
	transport, err := registry.CreateDNSTransport(ctx, logger, "dns-server", C.DNSTypeGroup, groupOptions)
	require.NoError(t, err)
	require.Equal(t, C.DNSTypeGroup, transport.Type())
	require.Equal(t, []string{"dns-server-1", "dns-server-2"}, transport.Dependencies())
	provider, err := registry.CreateDNSTransport(ctx, logger, "dns-server-2", C.DNSTypeProvider, servers[1].Options)
	require.NoError(t, err)
	require.Equal(t, C.DNSTypeProvider, provider.Type())
	require.Implements(t, (*adapter.DNSProviderTransport)(nil), provider)
	require.Implements(t, (*adapter.DNSGroupTransport)(nil), transport)
}

// "order": the first answers; a dead first costs the timeout of an attempt until it failed
// twice, then it is set aside and skipped, a probe brings it back and it is first again.
func TestGroupOrder(t *testing.T) {
	t.Parallel()
	first, second := newGroupTestMember("first", groupTestAnswer(1, 0)), newGroupTestMember("second", groupTestAnswer(2, 0))
	group, output := newGroupTest(t, nil, C.DNSGroupStrategyOrder, false, first, second)
	groupTestExpect(t, group, "10.0.0.1")
	groupTestExpect(t, group, "10.0.0.1")
	if asked := second.asked(); asked != 0 {
		t.Fatalf("the second asked %d times while the first answers", asked)
	}

	first.serve(groupTestSilent)
	// measured now: 4 times its smoothed time, at least attemptMin
	elapsed := groupTestExpect(t, group, "10.0.0.2")
	if elapsed < groupTestTiming.attemptMin {
		t.Errorf("the second answered after %v, before the timeout of the first", elapsed)
	}
	if state := group.testMember("first"); state.SetAside || state.Failures != 1 {
		t.Fatalf("first %+v after one failure", state)
	}
	groupTestExpect(t, group, "10.0.0.2")
	if state := group.testMember("first"); !state.SetAside || state.Failures != 2 {
		t.Fatalf("first %+v after two failures, want it set aside", state)
	}
	if !output.has("server first failed 2 times in a row (context deadline exceeded), set aside until it answers again") {
		t.Errorf("no warning of the first set aside in:\n%s", output)
	}
	// set aside: skipped, no waiting, no probe before probeFirst
	asked := first.asked()
	if elapsed := groupTestExpect(t, group, "10.0.0.2"); elapsed > groupTestTiming.attemptMin {
		t.Errorf("the second answered after %v while the first is set aside", elapsed)
	}
	if first.asked() != asked {
		t.Fatal("the first was asked before its probe was due")
	}

	// the probe: a copy of a real query, in the background
	first.serve(groupTestAnswer(1, 0))
	time.Sleep(groupTestTiming.probeFirst + 50*time.Millisecond)
	groupTestExpect(t, group, "10.0.0.2")
	waitFallbackTest(t, "the first answers its probe", func() bool { return !group.testMember("first").SetAside })
	if !output.has("server first answers again") {
		t.Errorf("no warning of the first back in:\n%s", output)
	}
	groupTestExpect(t, group, "10.0.0.1") // first again at once
}

// A probe that gets no answer leaves the member aside; as in the fallback, the probes come
// probeFirst after it was set aside, probeFirst later, then twice as long each time, up to
// probeMax.
func TestGroupProbeBackoff(t *testing.T) {
	t.Parallel()
	first, second := newGroupTestMember("first", fallbackTestFails), newGroupTestMember("second", groupTestAnswer(2, 0))
	group, _ := newGroupTest(t, nil, C.DNSGroupStrategyOrder, false, first, second)
	groupTestExpect(t, group, "10.0.0.2")
	groupTestExpect(t, group, "10.0.0.2")
	require.True(t, group.testMember("first").SetAside)
	probes := func() int { return first.asked() - 2 }
	probeFirst := groupTestTiming.probeFirst
	for _, wait := range []time.Duration{probeFirst, probeFirst, 2 * probeFirst, groupTestTiming.probeMax, groupTestTiming.probeMax} {
		before := probes()
		// a query before the probe is due sends none
		time.Sleep(wait / 2)
		groupTestExpect(t, group, "10.0.0.2")
		if probes() != before {
			t.Fatalf("probe sent %v before it was due (wait %v)", wait/2, wait)
		}
		time.Sleep(wait/2 + 60*time.Millisecond)
		groupTestExpect(t, group, "10.0.0.2")
		waitFallbackTest(t, "the probe is sent", func() bool { return probes() == before+1 })
	}
	require.True(t, group.testMember("first").SetAside)
}

// "fastest": the member with the lowest smoothed time first, those not measured after the
// measured ones in the order of the list.
func TestGroupFastestOrder(t *testing.T) {
	t.Parallel()
	var members []adapter.DNSTransport
	for _, tag := range []string{"a", "b", "c", "d", "e"} {
		members = append(members, newGroupTestMember(tag, groupTestAnswer(1, 0)))
	}
	group, _ := newGroupTest(t, nil, C.DNSGroupStrategyFastest, false, members...)
	group.access.Lock()
	for _, member := range group.members {
		member.smoothed = map[string]time.Duration{"a": 0, "b": 40 * time.Millisecond, "c": 0, "d": 10 * time.Millisecond, "e": 20 * time.Millisecond}[member.tag]
	}
	group.members[4].down = true // e is set aside
	group.access.Unlock()
	plan, err := group.plan(context.Background(), freshTestQuery())
	require.NoError(t, err)
	var order []string
	for _, attempt := range plan.attempts {
		order = append(order, attempt.member.tag)
	}
	require.Equal(t, []string{"d", "b", "a", "c"}, order)
	// the timeout of an attempt: 4 times the smoothed time within [attemptMin, attemptMax],
	// attemptMax when not measured
	require.Equal(t, []time.Duration{50 * time.Millisecond, 160 * time.Millisecond, 300 * time.Millisecond, 300 * time.Millisecond},
		[]time.Duration{plan.attempts[0].timeout, plan.attempts[1].timeout, plan.attempts[2].timeout, plan.attempts[3].timeout})
}

// "fastest" measures every member with background copies, then asks the fastest, fails
// over to the next fastest, and refreshes old measurements without delaying a reply.
func TestGroupFastest(t *testing.T) {
	t.Parallel()
	slow := newGroupTestMember("slow", groupTestAnswer(1, 80*time.Millisecond))
	fast := newGroupTestMember("fast", groupTestAnswer(2, 5*time.Millisecond))
	mid := newGroupTestMember("mid", groupTestAnswer(3, 40*time.Millisecond))
	group, _ := newGroupTest(t, nil, C.DNSGroupStrategyFastest, false, slow, fast, mid)
	measured := func(tag string) func() bool {
		return func() bool { return group.testMember(tag).SmoothedTime > 0 }
	}
	// nothing measured: the order of the list; a copy measures the first not measured
	groupTestExpect(t, group, "10.0.0.1")
	waitFallbackTest(t, "fast is measured", measured("fast"))
	if mid.asked() != 0 {
		t.Fatal("more than one copy for one query")
	}
	groupTestExpect(t, group, "10.0.0.2") // measured before mid, which is not
	waitFallbackTest(t, "mid is measured", measured("mid"))
	for i := 0; i < 5; i++ {
		// the copies to the others (old measurements) never delay the reply of fast
		if elapsed := groupTestExpect(t, group, "10.0.0.2"); elapsed > 35*time.Millisecond {
			t.Errorf("fast answered after %v", elapsed)
		}
	}
	state := group.GroupState()
	if !(state.Members[1].SmoothedTime < state.Members[2].SmoothedTime && state.Members[2].SmoothedTime < state.Members[0].SmoothedTime) {
		t.Fatalf("smoothed times %+v", state.Members)
	}

	// old measurements are refreshed: one copy per query, to the oldest one
	time.Sleep(groupTestTiming.staleAfter + 50*time.Millisecond)
	slowAsked, midAsked := slow.asked(), mid.asked()
	groupTestExpect(t, group, "10.0.0.2")
	waitFallbackTest(t, "a copy to slow", func() bool { return slow.asked() == slowAsked+1 })
	groupTestExpect(t, group, "10.0.0.2")
	waitFallbackTest(t, "a copy to mid", func() bool { return mid.asked() == midAsked+1 })
	groupTestExpect(t, group, "10.0.0.2")
	time.Sleep(100 * time.Millisecond)
	if slow.asked() != slowAsked+1 || mid.asked() != midAsked+1 {
		t.Errorf("copies sent to fresh measurements: slow %d, mid %d", slow.asked()-slowAsked, mid.asked()-midAsked)
	}

	// fast fails: the next fastest answers
	fast.serve(fallbackTestFails)
	groupTestExpect(t, group, "10.0.0.3")
	if state := group.testMember("fast"); state.Failures != 1 {
		t.Errorf("fast %+v", state)
	}
}

// A copy that gets no answer is not sent again with the next query, but a minute (here
// staleAfter) later; a member that fails its copies twice is set aside.
func TestGroupFastestCopyFails(t *testing.T) {
	t.Parallel()
	fast := newGroupTestMember("fast", groupTestAnswer(1, 0))
	other := newGroupTestMember("other", groupTestRcode(mDNS.RcodeServerFailure))
	group, _ := newGroupTest(t, nil, C.DNSGroupStrategyFastest, false, fast, other)
	groupTestExpect(t, group, "10.0.0.1")
	waitFallbackTest(t, "the copy to other", func() bool { return other.asked() == 1 })
	for i := 0; i < 5; i++ {
		groupTestExpect(t, group, "10.0.0.1")
	}
	time.Sleep(50 * time.Millisecond)
	if asked := other.asked(); asked != 1 {
		t.Fatalf("a member that refuses got %d copies", asked)
	}
	other.serve(fallbackTestFails)
	time.Sleep(groupTestTiming.staleAfter)
	groupTestExpect(t, group, "10.0.0.1")
	waitFallbackTest(t, "a copy a while later", func() bool { return other.asked() == 2 })
	time.Sleep(groupTestTiming.staleAfter)
	groupTestExpect(t, group, "10.0.0.1")
	waitFallbackTest(t, "other set aside by its copies", func() bool { return group.testMember("other").SetAside })
}

// NOERROR and NXDOMAIN are answers; another rcode moves on without a failure, and when
// nobody answers, the first such reply is returned.
func TestGroupRcodes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		first    groupTestHandler
		second   groupTestHandler
		want     string
		failures [2]uint64
		askedTwo bool
	}{
		{"servfail then an answer", groupTestRcode(mDNS.RcodeServerFailure), groupTestAnswer(2, 0), "10.0.0.2", [2]uint64{0, 0}, true},
		{"refused as an error then servfail", func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
			return nil, RcodeRefused
		}, groupTestRcode(mDNS.RcodeServerFailure), "REFUSED", [2]uint64{0, 0}, true},
		{"servfail then a failure", groupTestRcode(mDNS.RcodeServerFailure), fallbackTestFails, "SERVFAIL", [2]uint64{0, 1}, true},
		{"nxdomain is an answer", groupTestRcode(mDNS.RcodeNameError), groupTestAnswer(2, 0), "NXDOMAIN", [2]uint64{0, 0}, false},
		{"a failure then refused", fallbackTestFails, groupTestRcode(mDNS.RcodeRefused), "REFUSED", [2]uint64{1, 0}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			first, second := newGroupTestMember("first", test.first), newGroupTestMember("second", test.second)
			// with the safety net: a query with an rcode never goes to the provider
			group, _ := newGroupTest(t, groupTestProviders(testResolver(t, mDNS.RcodeSuccess)), C.DNSGroupStrategyOrder, true, first, second)
			groupTestExpect(t, group, test.want)
			if got := [2]uint64{group.testMember("first").Failures, group.testMember("second").Failures}; got != test.failures {
				t.Errorf("failures %v, want %v", got, test.failures)
			}
			if (second.asked() == 1) != test.askedTwo {
				t.Errorf("second asked %d times", second.asked())
			}
		})
	}
}

// A caller that gives up gets its error at once and nothing is counted; a member cut by the
// caller's deadline before its time counts nothing either, one that had all of it fails.
func TestGroupCallerCancel(t *testing.T) {
	t.Parallel()
	silent, second := newGroupTestMember("silent", groupTestSilent), newGroupTestMember("second", groupTestAnswer(2, 0))
	group, _ := newGroupTest(t, nil, C.DNSGroupStrategyOrder, false, silent, second)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	startAt := time.Now()
	_, err := group.Exchange(ctx, freshTestQuery())
	if err == nil || time.Since(startAt) > 200*time.Millisecond {
		t.Fatalf("canceled query returned %v after %v", err, time.Since(startAt))
	}
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, err = group.Exchange(ctx, freshTestQuery())
	cancel()
	if err == nil {
		t.Fatal("no error after the deadline")
	}
	if state := group.testMember("silent"); state.Failures != 0 || state.SetAside {
		t.Fatalf("silent %+v after queries its callers gave up", state)
	}
	if second.asked() != 0 {
		t.Fatal("the second was asked for a query given up")
	}

	// the last step has the caller's whole deadline; when it was longer than the timeout of
	// an attempt, the member had its time and failed
	alone := newGroupTestMember("alone", groupTestSilent)
	group, _ = newGroupTest(t, nil, C.DNSGroupStrategyOrder, false, alone)
	ctx, cancel = context.WithTimeout(context.Background(), groupTestTiming.attemptMax+100*time.Millisecond)
	startAt = time.Now()
	_, err = group.Exchange(ctx, freshTestQuery())
	cancel()
	if err == nil || time.Since(startAt) < groupTestTiming.attemptMax+50*time.Millisecond {
		t.Fatalf("the last member was cut before the caller's deadline: %v after %v", err, time.Since(startAt))
	}
	if state := group.testMember("alone"); state.Failures != 1 {
		t.Errorf("alone %+v, want one failure", state)
	}
}

// When every member is set aside, all are asked in order, and the first to answer is back.
func TestGroupAllSetAside(t *testing.T) {
	t.Parallel()
	first, second := newGroupTestMember("first", fallbackTestFails), newGroupTestMember("second", fallbackTestFails)
	group, _ := newGroupTest(t, nil, C.DNSGroupStrategyOrder, false, first, second)
	group.timing.probeFirst = time.Minute // no probe in this test
	groupTestExpect(t, group, "error")
	groupTestExpect(t, group, "error")
	require.True(t, group.testMember("first").SetAside && group.testMember("second").SetAside)
	groupTestExpect(t, group, "error")
	require.Equal(t, []int{3, 3}, []int{first.asked(), second.asked()})
	second.serve(groupTestAnswer(2, 0))
	groupTestExpect(t, group, "10.0.0.2")
	require.Equal(t, 4, first.asked())
	require.False(t, group.testMember("second").SetAside)
	require.True(t, group.testMember("first").SetAside)
	groupTestExpect(t, group, "10.0.0.2")
	require.Equal(t, 4, first.asked(), "the first asked while the second is healthy")
}

// Failures of queries that fail together count once.
func TestGroupCountsBatchOnce(t *testing.T) {
	t.Parallel()
	const batch = 20
	release := make(chan struct{})
	var waiting sync.WaitGroup
	waiting.Add(batch)
	first := newGroupTestMember("first", func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		waiting.Done()
		<-release
		return nil, errFallbackTestServer
	})
	second := newGroupTestMember("second", groupTestAnswer(2, 0))
	group, _ := newGroupTest(t, nil, C.DNSGroupStrategyOrder, false, first, second)
	answers := make(chan string, batch)
	for i := 0; i < batch; i++ {
		go func() {
			got, _ := groupTestQuery(group)
			answers <- got
		}()
	}
	waiting.Wait()
	close(release)
	for i := 0; i < batch; i++ {
		if got := <-answers; got != "10.0.0.2" {
			t.Errorf("answered by %s", got)
		}
	}
	if state := group.testMember("first"); state.SetAside || state.Failures != batch {
		t.Fatalf("first %+v after %d queries failed at once, want it healthy", state, batch)
	}
	first.serve(fallbackTestFails)
	groupTestExpect(t, group, "10.0.0.2")
	require.True(t, group.testMember("first").SetAside, "a later failure did not set it aside")
}

// The safety net: when the fallback is enabled and no member is a provider server, a query
// every member failed with an error goes to the provider's servers.
func TestGroupSafetyNet(t *testing.T) {
	t.Parallel()
	t.Run("enabled", func(t *testing.T) {
		t.Parallel()
		first, second := newGroupTestMember("first", fallbackTestFails), newGroupTestMember("second", groupTestSilent)
		group, output := newGroupTest(t, groupTestProviders(testResolver(t, mDNS.RcodeSuccess)), C.DNSGroupStrategyOrder, true, first, second)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		response, err := group.Exchange(ctx, freshTestQuery())
		require.Equal(t, "1.2.3.4", groupTestWho(response, err))
		require.Equal(t, uint32(fallbackMaxTTL), response.Answer[0].Header().Ttl, "the answer of the net lives long")
		if second.asked() != 1 {
			t.Errorf("second asked %d times", second.asked())
		}
		state := group.GroupState()
		require.True(t, state.SafetyNet)
		require.False(t, state.SafetyNetAnswer.IsZero())
		for _, message := range []string{
			"group dns-server falls back to provider DNS when every server fails",
			"every server failed (server second: context deadline exceeded), answering from provider DNS 127.0.0.1 until one answers again",
		} {
			if !output.has(message) {
				t.Errorf("missing %q in:\n%s", message, output)
			}
		}
		first.serve(groupTestAnswer(1, 0))
		time.Sleep(groupTestTiming.probeFirst) // first is not set aside: one failure
		groupTestExpect(t, group, "10.0.0.1")
		if !output.has("server first answers, provider DNS no longer used") {
			t.Errorf("no warning of the net left in:\n%s", output)
		}
	})
	t.Run("not enabled", func(t *testing.T) {
		t.Parallel()
		first := newGroupTestMember("first", fallbackTestFails)
		group, output := newGroupTest(t, groupTestProviders(testResolver(t, mDNS.RcodeSuccess)), C.DNSGroupStrategyOrder, false, first)
		groupTestExpect(t, group, "error")
		require.False(t, group.GroupState().SafetyNet)
		require.False(t, output.has("provider"), output.String())
	})
	t.Run("a provider member", func(t *testing.T) {
		t.Parallel()
		first, provider := newGroupTestMember("first", fallbackTestFails), newGroupTestMember("isp", fallbackTestFails)
		provider.transportType = C.DNSTypeProvider
		group, output := newGroupTest(t, groupTestProviders(testResolver(t, mDNS.RcodeSuccess)), C.DNSGroupStrategyOrder, true, first, provider)
		groupTestExpect(t, group, "error")
		require.False(t, group.GroupState().SafetyNet)
		require.True(t, output.has("no provider DNS fallback for group dns-server: its server isp is the provider"), output.String())
	})
}

// The net is there only when one member at least would have the fallback alone: a list of
// local or private resolvers (a filter in the LAN, a server behind a VPN) keeps its queries
// from the provider, as one of them alone does.
func TestGroupSafetyNetPolicy(t *testing.T) {
	t.Parallel()
	providers := groupTestProviders(testResolver(t, mDNS.RcodeSuccess))
	lan, vpn, system := newGroupTestMember("lan", fallbackTestFails), newGroupTestMember("vpn", fallbackTestFails), newGroupTestMember("system", fallbackTestFails)
	lan.fallback, vpn.fallback = groupTestState("192.168.1.2"), groupTestState("100.71.54.2")
	system.transportType = C.DNSTypeLocal
	group, output := newGroupTest(t, providers, C.DNSGroupStrategyOrder, true, lan, vpn, system)
	groupTestExpect(t, group, "error")
	require.False(t, group.GroupState().SafetyNet)
	require.True(t, output.has("no provider DNS fallback for group dns-server: none of its servers would have it alone (lan: local or private address 192.168.1.2; vpn: local or private address 100.71.54.2; system: type local)"), output.String())
	require.False(t, output.has("answering from provider DNS"), output.String())

	// with a public server in the list, a query every member failed asks the provider
	lan, public := newGroupTestMember("lan", fallbackTestFails), newGroupTestMember("public", fallbackTestFails)
	lan.fallback = groupTestState("192.168.1.2")
	group, output = newGroupTest(t, providers, C.DNSGroupStrategyOrder, true, lan, public)
	groupTestExpect(t, group, "1.2.3.4")
	require.True(t, output.has("group dns-server falls back to provider DNS when every server fails"), output.String())
}

// A change of state caused by a query of sing-box itself, whose lines are lowered to the
// debug level, is still written at the warn level.
func TestGroupStateLinesOfOwnQueries(t *testing.T) {
	t.Parallel()
	output := new(lockedBuffer)
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now(), DisableColors: true}, output, "", nil, false)
	factory.SetLevel(log.LevelWarn)
	require.NoError(t, factory.Start())
	first, second := newGroupTestMember("first", fallbackTestFails), newGroupTestMember("second", groupTestAnswer(2, 0))
	group, err := newGroupTransport(context.Background(), factory.NewLogger("dns/group[dns-server]"), "dns-server", option.GroupDNSServerOptions{Servers: []string{"first", "second"}}, false)
	require.NoError(t, err)
	group.timing = groupTestTiming
	require.NoError(t, group.resolveMembers(&fakeDNSTransportManager{transports: map[string]adapter.DNSTransport{"first": first, "second": second}}))
	t.Cleanup(func() { group.close() })
	own := func() {
		ctx, cancel := context.WithTimeout(log.ContextWithOverrideLevel(context.Background(), log.LevelDebug), 5*time.Second)
		defer cancel()
		response, err := group.Exchange(ctx, freshTestQuery())
		require.Equal(t, "10.0.0.2", groupTestWho(response, err))
	}
	own()
	own()
	require.True(t, output.has("server first failed 2 times in a row"), output.String())
	require.False(t, output.has("asking the next one") || output.has("failed: "), "a single query stays at the debug level:\n%s", output)
	first.serve(groupTestAnswer(1, 0))
	time.Sleep(groupTestTiming.probeFirst + 50*time.Millisecond)
	own()
	waitFallbackTest(t, "first answers its probe", func() bool { return output.has("server first answers again") })
}

// An answer of the net to a query planned before a member answered again leaves the net
// unused: no line of the net taking over just after the member came back.
func TestGroupSafetyNetLateAnswer(t *testing.T) {
	t.Parallel()
	first := newGroupTestMember("first", fallbackTestFails)
	group, output := newGroupTest(t, groupTestProviders(testResolver(t, mDNS.RcodeSuccess)), C.DNSGroupStrategyOrder, true, first)
	plan, err := group.plan(context.Background(), freshTestQuery())
	require.NoError(t, err)
	require.NotNil(t, plan.net)
	group.answered(context.Background(), group.members[0], plan.epoch, time.Millisecond)
	group.netAnswered(context.Background(), plan, errGroupSetAside)
	require.False(t, output.has("answering from provider DNS"), output.String())
	require.False(t, group.GroupState().SafetyNetAnswer.IsZero(), "the time of the answer is kept")
	plan, err = group.plan(context.Background(), freshTestQuery())
	require.NoError(t, err)
	group.netAnswered(context.Background(), plan, errGroupSetAside)
	require.True(t, output.has("answering from provider DNS"), output.String())
}

// With the safety net, a group whose members are all set aside answers from the provider at
// once and probes the members; when the provider fails too, the members are asked in order.
func TestGroupSafetyNetFirst(t *testing.T) {
	t.Parallel()
	t.Run("provider answers", func(t *testing.T) {
		t.Parallel()
		first, second := newGroupTestMember("first", fallbackTestFails), newGroupTestMember("second", fallbackTestFails)
		group, _ := newGroupTest(t, groupTestProviders(testResolver(t, mDNS.RcodeSuccess)), C.DNSGroupStrategyOrder, true, first, second)
		groupTestExpect(t, group, "1.2.3.4")
		groupTestExpect(t, group, "1.2.3.4")
		require.True(t, group.testMember("first").SetAside && group.testMember("second").SetAside)
		groupTestExpect(t, group, "1.2.3.4")
		require.Equal(t, []int{2, 2}, []int{first.asked(), second.asked()}, "members set aside asked before the provider")
		second.serve(groupTestAnswer(2, 0))
		time.Sleep(groupTestTiming.probeFirst + 50*time.Millisecond)
		groupTestExpect(t, group, "1.2.3.4")
		waitFallbackTest(t, "second answers its probe", func() bool { return !group.testMember("second").SetAside })
		waitFallbackTest(t, "first is probed", func() bool { return first.asked() == 3 })
		groupTestExpect(t, group, "10.0.0.2")
	})
	t.Run("provider fails", func(t *testing.T) {
		t.Parallel()
		first, second := newGroupTestMember("first", fallbackTestFails), newGroupTestMember("second", fallbackTestFails)
		group, _ := newGroupTest(t, groupTestProviders(testResolver(t, mDNS.RcodeRefused)), C.DNSGroupStrategyOrder, true, first, second)
		group.timing.probeFirst = time.Minute // no probe in this test
		groupTestExpect(t, group, "error")
		groupTestExpect(t, group, "error")
		require.True(t, group.testMember("first").SetAside && group.testMember("second").SetAside)
		second.serve(groupTestAnswer(2, 0))
		groupTestExpect(t, group, "10.0.0.2")
		require.Equal(t, []int{3, 3}, []int{first.asked(), second.asked()})
		require.False(t, group.testMember("second").SetAside)
	})
}

// A member has no per-server fallback: neither through the group nor asked alone; the group
// itself has none either.
func TestGroupMembersWithoutFallback(t *testing.T) {
	t.Parallel()
	member, state, _ := newFallbackTest(testResolver(t, mDNS.RcodeSuccess))
	member.transportTag = "member"
	member.serve(fallbackTestFails)
	require.NotNil(t, fallbackFor(member))
	group, output := newGroupTest(t, nil, C.DNSGroupStrategyOrder, false, member)
	require.Nil(t, fallbackFor(member), "a member keeps its fallback")
	require.True(t, state.grouped.Load())
	require.True(t, output.has("no provider DNS fallback for server member: member of group dns-server"), output.String())
	groupTestExpect(t, group, "error")
	client := &Client{ctx: context.Background()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if got, err := fallbackTestAnswer(client.exchangeTransport(ctx, member, freshTestQuery())); got != "" || err != errFallbackTestServer {
		t.Errorf("the member asked alone answered by %q (%v), want its own error", got, err)
	}
	require.Nil(t, fallbackFor(group))
	if got := state.testState(); got.failures != 0 || got.down {
		t.Errorf("the fallback state of the member moved: %+v", got)
	}
}

// A network reset clears failures, the set-aside state and measurements; what was on its
// way before counts nothing.
func TestGroupReset(t *testing.T) {
	t.Parallel()
	first, second := newGroupTestMember("first", fallbackTestFails), newGroupTestMember("second", groupTestAnswer(2, 0))
	group, output := newGroupTest(t, nil, C.DNSGroupStrategyOrder, false, first, second)
	groupTestExpect(t, group, "10.0.0.2")
	groupTestExpect(t, group, "10.0.0.2")
	require.True(t, group.testMember("first").SetAside)
	require.NotZero(t, group.testMember("second").SmoothedTime)
	group.Reset()
	state := group.GroupState()
	require.False(t, state.Members[0].SetAside)
	require.Zero(t, state.Members[1].SmoothedTime)
	require.Equal(t, uint64(2), state.Members[0].Failures, "the counts since the start are kept")
	require.True(t, output.has("network reset: servers set aside are asked again: first"), output.String())

	// a query on its way across a reset
	called, release := make(chan struct{}), make(chan struct{})
	first.serve(func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
		close(called)
		<-release
		return nil, errFallbackTestServer
	})
	done := make(chan string)
	go func() {
		got, _ := groupTestQuery(group)
		done <- got
	}()
	<-called
	group.Reset()
	close(release)
	require.Equal(t, "10.0.0.2", <-done)
	state = group.GroupState()
	require.Equal(t, uint64(2), state.Members[0].Failures, "a failure from before the reset counted")
	require.Equal(t, uint64(2), state.Members[1].Answers, "an answer from before the reset counted")
	require.Zero(t, state.Members[1].SmoothedTime)
}

// The close of the group ends the background copies and waits for them; none starts after.
func TestGroupCloseEndsCopies(t *testing.T) {
	t.Parallel()
	fast, hanging := newGroupTestMember("fast", groupTestAnswer(1, 0)), newGroupTestMember("hanging", groupTestSilent)
	group, _ := newGroupTest(t, nil, C.DNSGroupStrategyFastest, false, fast, hanging)
	group.timing.attemptMax = 10 * time.Second // the copy would wait that long
	groupTestExpect(t, group, "10.0.0.1")
	waitFallbackTest(t, "the copy to hanging", func() bool { return hanging.asked() == 1 })
	startAt := time.Now()
	require.NoError(t, group.close())
	if elapsed := time.Since(startAt); elapsed > time.Second {
		t.Fatalf("close took %v", elapsed)
	}
	group.timing.staleAfter = 0
	groupTestExpect(t, group, "10.0.0.1")
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, 1, hanging.asked(), "a copy sent after the close")
	require.Zero(t, group.testMember("hanging").Failures, "the close counted as a failure")
}

// ExchangeAsync calls back once, from another goroutine.
func TestGroupExchangeAsync(t *testing.T) {
	t.Parallel()
	first := newGroupTestMember("first", groupTestAnswer(1, 20*time.Millisecond))
	group, _ := newGroupTest(t, nil, C.DNSGroupStrategyOrder, false, first)
	results := make(chan string, 2)
	startAt := time.Now()
	group.ExchangeAsync(context.Background(), freshTestQuery(), func(response *mDNS.Msg, err error) {
		results <- groupTestWho(response, err)
	})
	if time.Since(startAt) > 10*time.Millisecond {
		t.Error("ExchangeAsync kept the caller")
	}
	require.Equal(t, "10.0.0.1", <-results)
	select {
	case <-results:
		t.Fatal("called back twice")
	case <-time.After(50 * time.Millisecond):
	}
}

// Many queries at once, with network resets and readers of the state, members answering,
// failing, refusing and hanging at random (go test -race).
func TestGroupRace(t *testing.T) {
	t.Parallel()
	for _, strategy := range []string{C.DNSGroupStrategyOrder, C.DNSGroupStrategyFastest} {
		t.Run(strategy, func(t *testing.T) {
			t.Parallel()
			random := func(n byte) groupTestHandler {
				return func(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
					switch rand.IntN(10) {
					case 0:
						return nil, errFallbackTestServer
					case 1:
						return groupTestRcode(mDNS.RcodeServerFailure)(ctx, message)
					case 2:
						return groupTestSilent(ctx, message)
					default:
						return groupTestAnswer(n, time.Duration(rand.IntN(5))*time.Millisecond)(ctx, message)
					}
				}
			}
			var members []adapter.DNSTransport
			for n, tag := range []string{"a", "b", "c"} {
				members = append(members, newGroupTestMember(tag, random(byte(n+1))))
			}
			group, _ := newGroupTest(t, groupTestProviders(testResolver(t, mDNS.RcodeSuccess)), strategy, true, members...)
			group.timing.attemptMax = 30 * time.Millisecond
			group.timing.attemptMin = 10 * time.Millisecond
			group.timing.probeFirst = 5 * time.Millisecond
			group.timing.probeMax = 20 * time.Millisecond
			group.timing.staleAfter = 5 * time.Millisecond
			stop := make(chan struct{})
			var others sync.WaitGroup
			others.Add(1)
			go func() {
				defer others.Done()
				for {
					select {
					case <-stop:
						return
					case <-time.After(3 * time.Millisecond):
					}
					if rand.IntN(4) == 0 {
						group.Reset()
					}
					group.GroupState()
				}
			}()
			var queries sync.WaitGroup
			var answered atomic.Int32
			for i := 0; i < 32; i++ {
				queries.Add(1)
				go func() {
					defer queries.Done()
					for j := 0; j < 30; j++ {
						ctx, cancel := context.WithTimeout(context.Background(), time.Second)
						if j%7 == 0 {
							time.AfterFunc(time.Duration(rand.IntN(20))*time.Millisecond, cancel)
						}
						response, err := group.Exchange(ctx, freshTestQuery())
						cancel()
						if err == nil && response != nil {
							answered.Add(1)
						}
					}
				}()
			}
			queries.Wait()
			close(stop)
			others.Wait()
			startAt := time.Now()
			require.NoError(t, group.close())
			require.Less(t, time.Since(startAt), time.Second, "close waited for the background copies")
			require.Greater(t, answered.Load(), int32(0))
		})
	}
}

// A member that gives no answer in its time has the rest asked together: the answer comes one
// timeout after the query, not one per dead member, and the members it cut count nothing.
func TestGroupTogetherAfterTimeout(t *testing.T) {
	t.Parallel()
	first, second, third := newGroupTestMember("first", groupTestSilent), newGroupTestMember("second", groupTestSilent), newGroupTestMember("third", groupTestSilent)
	fourth := newGroupTestMember("fourth", groupTestAnswer(4, 0))
	group, output := newGroupTest(t, nil, C.DNSGroupStrategyOrder, false, first, second, third, fourth)
	elapsed := groupTestExpect(t, group, "10.0.0.4")
	if elapsed < groupTestTiming.attemptMax || elapsed > 2*groupTestTiming.attemptMax {
		t.Errorf("answered after %v, want one timeout of %v", elapsed, groupTestTiming.attemptMax)
	}
	// the members cut by the answer may be called after it, with their context done already
	require.Eventually(t, func() bool {
		return first.asked() == 1 && second.asked() == 1 && third.asked() == 1 && fourth.asked() == 1
	}, time.Second, 5*time.Millisecond, "each member asked once")
	require.Equal(t, uint64(1), group.testMember("first").Failures)
	require.Zero(t, group.testMember("second").Failures, "cut by the answer of the fourth")
	require.Zero(t, group.testMember("third").Failures, "cut by the answer of the fourth")
	require.True(t, output.has("server first gave no answer in 300ms, asking the other 3 together"), output.String())

	// a first member that answers: nobody else is asked
	first.serve(groupTestAnswer(1, 0))
	groupTestExpect(t, group, "10.0.0.1")
	require.Equal(t, []int{1, 1, 1}, []int{second.asked(), third.asked(), fourth.asked()})
}

// Every member dead, the safety net behind them: the first times out, the rest together, then the
// provider; each member had its whole time and counts one failure.
func TestGroupTogetherThenSafetyNet(t *testing.T) {
	t.Parallel()
	members := make([]adapter.DNSTransport, 4)
	for index := range members {
		members[index] = newGroupTestMember("m"+strconv.Itoa(index+1), groupTestSilent)
	}
	group, _ := newGroupTest(t, groupTestProviders(testResolver(t, mDNS.RcodeSuccess)), C.DNSGroupStrategyOrder, true, members...)
	elapsed := groupTestExpect(t, group, "1.2.3.4")
	if elapsed > 3*groupTestTiming.attemptMax {
		t.Errorf("the provider answered after %v; one after another the members alone take %v", elapsed, 4*groupTestTiming.attemptMax)
	}
	for index := range members {
		tag := "m" + strconv.Itoa(index+1)
		require.Equal(t, uint64(1), group.testMember(tag).Failures, tag)
	}
}

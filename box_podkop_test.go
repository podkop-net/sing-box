package box_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// testServer stands for a server: it dials the destination itself, can be told to fail its
// start, and records its close.
type testServer struct {
	outbound.Adapter
	fail   bool
	closed atomic.Bool
}

type testServerOptions struct {
	Fail    bool `json:"fail,omitempty"`
	Version int  `json:"version,omitempty"`
}

func newTestServer(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options testServerOptions) (adapter.Outbound, error) {
	return &testServer{Adapter: outbound.NewAdapter("testserver", tag, []string{N.NetworkTCP, N.NetworkUDP}, nil), fail: options.Fail}, nil
}

func (s *testServer) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		scope.Add(func() error {
			s.closed.Store(true)
			return nil
		})
	case adapter.StartStateStart:
		if s.fail {
			return E.New("this server does not start")
		}
	}
	return nil
}

func (s *testServer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

func (s *testServer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

type quietWriter struct{}

func (quietWriter) WriteMessage(log.Level, string) {}

// hotTest is a started box of the servers s1 and s2, a urltest group g of them and a selector
// sel of the group and the servers, as podkop makes a section of a group.
type hotTest struct {
	t       *testing.T
	ctx     context.Context
	box     *box.Box
	history *urltest.HistoryStorage
	link    string
	target  string
}

func newHotTest(t *testing.T) *hotTest {
	t.Cleanup(box.DrainEvery(time.Hour))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	// what the connections of the tests go to: it holds them open until they are closed
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				conn.Read(make([]byte, 1))
				conn.Close()
			}()
		}
	}()
	registry := include.OutboundRegistry()
	outbound.Register[testServerOptions](registry, "testserver", newTestServer)
	history := urltest.NewHistoryStorage()
	ctx := service.ContextWithPtr(service.ContextWith(context.Background(), deprecated.NewStderrManager(log.StdLogger())), history)
	ctx = box.Context(ctx, include.InboundRegistry(), registry, include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry(), include.CertificateProviderRegistry())
	test := &hotTest{t: t, ctx: ctx, history: history, link: server.URL, target: listener.Addr().String()}
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"log": {"level": "error"},
		"outbounds": [
			{"type": "direct", "tag": "direct-out"},
			{"type": "testserver", "tag": "s1"},
			{"type": "testserver", "tag": "s2"},
			`+test.group("g", "s1", "s2")+`,
			{"type": "selector", "tag": "sel", "outbounds": ["g", "s1", "s2"], "default": "g"}
		]
	}`))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options, PlatformLogWriter: quietWriter{}})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { instance.Close() })
	test.box = instance
	require.Eventually(t, func() bool {
		return test.tested("s1") && test.tested("s2")
	}, 5*time.Second, 10*time.Millisecond)
	test.outbound("g").(interface{ CheckOutbounds() }).CheckOutbounds()
	return test
}

func (h *hotTest) group(tag string, members ...string) string {
	return `{"type": "urltest", "tag": "` + tag + `", "outbounds": ["` + strings.Join(members, `", "`) + `"], "url": "` + h.link + `", "interval": "1m"}`
}

func (h *hotTest) outbound(tag string) adapter.Outbound {
	found, loaded := h.box.Outbound().Outbound(tag)
	require.True(h.t, loaded, tag)
	return found
}

func (h *hotTest) server(tag string) *testServer {
	return h.outbound(tag).(*testServer)
}

func (h *hotTest) group1(tag string) adapter.URLTestGroup {
	return h.outbound(tag).(adapter.URLTestGroup)
}

func (h *hotTest) tested(tag string) bool {
	return h.history.LoadURLTestHistory(tag) != nil
}

// parse reads outbounds written as in a configuration.
func (h *hotTest) parse(outbounds string) []option.Outbound {
	options, err := json.UnmarshalExtendedContext[option.Options](h.ctx, []byte(`{"outbounds": [`+outbounds+`]}`))
	require.NoError(h.t, err)
	return options.Outbounds
}

// update gives the outbounds, written as in a configuration.
func (h *hotTest) update(outbounds string, remove []string, limit int) (box.OutboundUpdate, error) {
	return h.box.UpdateOutbounds(h.parse(outbounds), remove, limit)
}

// replaceS2 is the change of a server under its tag: s2, the group and the selector are
// replaced, s3 added, s1 stays.
func (h *hotTest) replaceS2() box.OutboundUpdate {
	update, err := h.update(`{"type": "testserver", "tag": "s2", "version": 2}, {"type": "testserver", "tag": "s3"}, `+
		h.group("g", "s1", "s2", "s3")+`, {"type": "selector", "tag": "sel", "outbounds": ["g", "s1", "s2", "s3"], "default": "g"}`, nil, 0)
	require.NoError(h.t, err)
	return update
}

func (h *hotTest) dial(through adapter.Outbound) net.Conn {
	conn, err := through.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr(h.target))
	require.NoError(h.t, err)
	h.t.Cleanup(func() { conn.Close() })
	return conn
}

// track lists a connection with the chain in the Clash API, as the router does.
func (h *hotTest) track(chain ...adapter.Outbound) net.Conn {
	client, server := net.Pipe()
	h.t.Cleanup(func() { server.Close() })
	tracked := h.box.TrafficManager().RoutedConnection(context.Background(), client, adapter.InboundContext{OutboundChain: chain}, nil, chain[0])
	h.t.Cleanup(func() { tracked.Close() })
	return tracked
}

// The new outbounds take the tags; the server that did not change stays the same object; the
// group that is replaced stops, and the new one keeps its choice of that server and tests the
// servers without a result.
func TestUpdateOutbounds(t *testing.T) {
	h := newHotTest(t)
	s1, s2, g, sel := h.outbound("s1"), h.outbound("s2"), h.outbound("g"), h.outbound("sel")
	chosen := g.(adapter.OutboundGroup).Selected(N.NetworkTCP)
	require.NotNil(t, chosen)
	h.history.DeleteURLTestHistory("s2") // what the backend does for a server that changed

	update := h.replaceS2()
	require.Equal(t, box.OutboundUpdate{Added: 1, Replaced: 3, Removed: 0, Kept: 3}, update)
	require.Same(t, s1, h.outbound("s1"))
	require.NotSame(t, s2, h.outbound("s2"))
	require.NotSame(t, g, h.outbound("g"))
	require.NotSame(t, sel, h.outbound("sel"))
	require.Equal(t, []string{"g", "s1", "s2", "s3"}, h.outbound("sel").(adapter.OutboundGroup).All())
	if chosen == s1 {
		require.Same(t, s1, h.group1("g").Selected(N.NetworkTCP), "the choice of the group before")
	}
	_, err := g.(adapter.URLTestGroup).URLTest(context.Background())
	require.Error(t, err, "the group before is stopped")
	require.Eventually(t, func() bool { return h.tested("s3") && h.tested("s2") }, 5*time.Second, 10*time.Millisecond)

	// what goes through the new selector goes through the new group
	h.dial(h.outbound("sel"))
	require.NotEmpty(t, h.outbound("g").(interface{ MembersInUse() []adapter.Outbound }).MembersInUse())

	// a server taken out, and the group without it
	update, err = h.update(h.group("g", "s2", "s3")+`, {"type": "selector", "tag": "sel", "outbounds": ["g", "s2", "s3"], "default": "g"}`, []string{"s1"}, 0)
	require.NoError(t, err)
	require.Equal(t, box.OutboundUpdate{Added: 0, Replaced: 2, Removed: 1, Kept: 6}, update)
	_, loaded := h.box.Outbound().Outbound("s1")
	require.False(t, loaded)
}

// What the groups found through an outbound that is replaced is not kept for the one that takes
// its tag: the new group tests it, while an outbound that stays keeps its result.
func TestUpdateOutboundsForgetsTheReplaced(t *testing.T) {
	h := newHotTest(t)
	s1Before, s2Before := h.history.LoadURLTestHistory("s1"), h.history.LoadURLTestHistory("s2")
	require.NotNil(t, s2Before)
	h.replaceS2()
	require.Eventually(t, func() bool {
		result := h.history.LoadURLTestHistory("s2")
		return result != nil && result.Time.After(s2Before.Time)
	}, 5*time.Second, 10*time.Millisecond, "s2 tested anew")
	require.Equal(t, s1Before.Time, h.history.LoadURLTestHistory("s1").Time, "s1 stays and is not tested")
}

// An update that would leave an outbound with one that goes is refused before anything is
// built, and changes nothing.
func TestUpdateOutboundsRefused(t *testing.T) {
	h := newHotTest(t)
	s2, g := h.outbound("s2"), h.outbound("g")
	_, err := h.update(`{"type": "testserver", "tag": "s2", "version": 2}`, nil, 0)
	require.ErrorContains(t, err, "goes through s2")
	_, err = h.update(``, []string{"s2"}, 0)
	require.ErrorContains(t, err, "goes through s2")
	_, err = h.box.UpdateOutbounds(append(h.parse(`{"type": "testserver", "tag": "s3"}`), h.parse(`{"type": "testserver", "tag": "s3"}`)...), nil, 0)
	require.ErrorContains(t, err, "duplicate")
	_, err = h.update(`{"type": "testserver", "tag": "s3"}`, []string{"missing"}, 0)
	require.ErrorContains(t, err, "not found")
	// a new group of a server taken out would keep the server it found at its start
	_, err = h.update(h.group("g", "s1", "s2")+`, {"type": "selector", "tag": "sel", "outbounds": ["g", "s1"], "default": "g"}`, []string{"s2"}, 0)
	require.ErrorContains(t, err, "goes through s2, which is removed")
	require.Same(t, s2, h.outbound("s2"))
	require.Same(t, g, h.outbound("g"))
	require.Zero(t, h.box.KeptOutbounds())
}

// An update that fails puts the outbounds of before back and closes the new ones, whether it
// fails in the first layer or after some were in place.
func TestUpdateOutboundsRollsBack(t *testing.T) {
	h := newHotTest(t)
	s2, g, sel := h.outbound("s2"), h.outbound("g"), h.outbound("sel")

	_, err := h.update(`{"type": "testserver", "tag": "s2", "fail": true}, `+h.group("g", "s1", "s2")+
		`, {"type": "selector", "tag": "sel", "outbounds": ["g", "s1", "s2"], "default": "g"}`, nil, 0)
	require.ErrorContains(t, err, "does not start")
	require.Same(t, s2, h.outbound("s2"))
	require.Same(t, g, h.outbound("g"))
	require.Same(t, sel, h.outbound("sel"))

	// the selector fails after the server and the group are in place
	_, err = h.update(`{"type": "testserver", "tag": "s3"}, `+h.group("g", "s1", "s3")+
		`, {"type": "selector", "tag": "sel", "outbounds": ["g", "s1", "missing"], "default": "g"}`, nil, 0)
	require.ErrorContains(t, err, "missing")
	_, loaded := h.box.Outbound().Outbound("s3")
	require.False(t, loaded, "the server added is taken out again")
	require.Same(t, g, h.outbound("g"))
	require.Same(t, sel, h.outbound("sel"))
	require.Zero(t, h.box.KeptOutbounds())
	// the group before still works
	_, err = g.(adapter.URLTestGroup).URLTest(context.Background())
	require.NoError(t, err)
}

// An outbound replaced is kept while a connection in the list goes through it, and not
// before drainMin is over; then closed, the groups too.
func TestDrainKeepsWhatCarriesConnections(t *testing.T) {
	h := newHotTest(t)
	s2, g, sel := h.server("s2"), h.outbound("g"), h.outbound("sel")
	h.replaceS2()
	tracked := h.track(sel, g, s2)

	now := time.Now()
	require.True(t, h.box.DrainOnce(now.Add(box.DrainMin/2)))
	require.Equal(t, 3, h.box.KeptOutbounds(), "not before drainMin")
	require.True(t, h.box.DrainOnce(now.Add(box.DrainMin+time.Second)))
	require.Equal(t, 3, h.box.KeptOutbounds(), "a connection goes through them")
	require.False(t, s2.closed.Load())

	tracked.Close()
	require.False(t, h.box.DrainOnce(now.Add(box.DrainMin+time.Second)))
	require.Zero(t, h.box.KeptOutbounds())
	require.True(t, s2.closed.Load(), "closed alone, out of the scope of the box")
	require.False(t, h.server("s1").closed.Load())
}

// The member a group dialed is kept while the connection is open, whatever the chain of the
// connection says.
func TestDrainFollowsTheDialsOfAGroup(t *testing.T) {
	h := newHotTest(t)
	g := h.outbound("g")
	conn := h.dial(g)
	used := g.(interface{ MembersInUse() []adapter.Outbound }).MembersInUse()
	require.Len(t, used, 1)
	member := used[0].(*testServer)

	_, err := h.update(`{"type": "testserver", "tag": "s1", "version": 2}, {"type": "testserver", "tag": "s2", "version": 2}, `+
		h.group("g", "s1", "s2")+`, {"type": "selector", "tag": "sel", "outbounds": ["g", "s1", "s2"], "default": "g"}`, nil, 0)
	require.NoError(t, err)
	later := time.Now().Add(box.DrainMin + time.Second)
	require.True(t, h.box.DrainOnce(later))
	require.True(t, h.box.DrainOnce(later), "asked again")
	require.False(t, member.closed.Load())
	require.Equal(t, 2, h.box.KeptOutbounds(), "the group and its member; the other server and the selector are closed")

	conn.Close()
	require.False(t, h.box.DrainOnce(later))
	require.True(t, member.closed.Load())
}

// After drainMax an outbound is closed though a connection goes through it.
func TestDrainMax(t *testing.T) {
	h := newHotTest(t)
	s2, g, sel := h.server("s2"), h.outbound("g"), h.outbound("sel")
	h.replaceS2()
	h.track(sel, g, s2)
	require.False(t, h.box.DrainOnce(time.Now().Add(box.DrainMax+time.Second)))
	require.True(t, s2.closed.Load())
}

// An outbound UpdateOutbounds started is closed by its own scope when it is replaced in turn,
// and with the box when it is still in place.
func TestHotOutboundsClosed(t *testing.T) {
	h := newHotTest(t)
	h.replaceS2()
	s2, s3 := h.server("s2"), h.server("s3")
	_, err := h.update(`{"type": "testserver", "tag": "s2", "version": 3}, `+h.group("g", "s1", "s2", "s3")+
		`, {"type": "selector", "tag": "sel", "outbounds": ["g", "s1", "s2", "s3"], "default": "g"}`, nil, 0)
	require.NoError(t, err)
	require.False(t, h.box.DrainOnce(time.Now().Add(box.DrainMin+time.Second)))
	require.True(t, s2.closed.Load())
	require.False(t, s3.closed.Load())
	last := h.server("s2")
	require.NoError(t, h.box.Close())
	require.True(t, last.closed.Load())
	require.True(t, s3.closed.Load())
	_, err = h.update(`{"type": "testserver", "tag": "s4"}`, nil, 0)
	require.ErrorContains(t, err, "closed")
}

// Beyond the limit of the servers kept the update is refused: the caller makes a new box.
func TestUpdateOutboundsLimit(t *testing.T) {
	h := newHotTest(t)
	h.replaceS2()
	_, err := h.update(`{"type": "testserver", "tag": "s4"}`, nil, 1)
	require.NoError(t, err, "one server kept")
	h.replaceS2()
	_, err = h.update(`{"type": "testserver", "tag": "s5"}`, nil, 1)
	require.ErrorIs(t, err, box.ErrTooManyKept)
	_, loaded := h.box.Outbound().Outbound("s5")
	require.False(t, loaded)
}

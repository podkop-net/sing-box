package urltestgroup

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// lossProbeServer serves the loss URL and counts what is asked of it, by the size of the probe.
type lossProbeServer struct {
	*httptest.Server
	access sync.Mutex
	sizes  map[int64]int
}

func newLossProbeServer(t *testing.T) *lossProbeServer {
	s := &lossProbeServer{sizes: make(map[int64]int)}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var last int64
		fmt.Sscanf(r.Header.Get("Range"), "bytes=0-%d", &last)
		s.access.Lock()
		s.sizes[last+1]++
		s.access.Unlock()
		// less than asked: at the window of a probe a megabyte takes seconds here, and the probes of
		// the process come one after another
		body := make([]byte, min(last+1, lossProbeBody))
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.Write(body)
	}))
	t.Cleanup(s.Server.Close)
	return s
}

// lossProbeBody is what the loss URLs of the tests serve at most: a probe counts a body shorter than
// it asked for as far as it goes.
const lossProbeBody = 32 << 10

// probes are the small (periodic) and the large (before a switch) probes asked for.
func (s *lossProbeServer) probes() (small int, large int) {
	s.access.Lock()
	defer s.access.Unlock()
	return s.sizes[urltest.LossProbeSmall], s.sizes[urltest.LossProbeLarge]
}

// requireNoProbe holds that no probe comes: the spacing of the tests is 0 (TestMain), so one that
// was started is there at once.
func (s *lossProbeServer) requireNoProbe(t *testing.T, message string) {
	t.Helper()
	require.Never(t, func() bool {
		small, large := s.probes()
		return small+large > 0
	}, 500*time.Millisecond, 20*time.Millisecond, message)
}

func (s *lossProbeServer) forget() {
	s.access.Lock()
	defer s.access.Unlock()
	clear(s.sizes)
}

// reserveStand is a group of one server with a fallback of its own: a group of the servers b and c,
// in a mode that counts the loss.
type reserveStand struct {
	loss          *lossProbeServer
	mainDead      atomic.Bool
	main, reserve *URLTest
	target        M.Socksaddr
}

func newReserveStand(t *testing.T, mode string) *reserveStand {
	// a delay of less than a millisecond is 0, and a member of delay 0 gives way to any other: the
	// choice of the reserve would wander, with a probe before each switch
	link, _ := testURL(t, 5*time.Millisecond)
	s := &reserveStand{loss: newLossProbeServer(t), target: balanceTarget(t)}
	a := newTestMember(C.TypeVLESS, "a", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if s.mainDead.Load() {
			return nil, syscall.ECONNREFUSED
		}
		return dialWorking(ctx, network, destination)
	})
	b, c := newTestMember(C.TypeSOCKS, "b", dialProbe), newTestMember(C.TypeSOCKS, "c", dialProbe)
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	manager := &testOutboundManager{members: map[string]adapter.Outbound{"a": a, "b": b, "c": c}}
	newGroup := func(tag string, mode string, outbounds, fallbacks []adapter.Outbound) *URLTest {
		logger := formattingLogger(t)
		group, err := NewURLTestGroup(ctx, manager, logger, outbounds, fallbacks, link, "", time.Minute, 50, 0, false)
		require.NoError(t, err)
		t.Cleanup(func() { group.Close() })
		group.mode, group.loss, err = groupMode(mode, s.loss.URL, 0, 0, 0, 0)
		require.NoError(t, err)
		// every round probes
		group.loss.interval = time.Nanosecond
		if mode == modeBalance {
			group.balance.Store(newBalancer())
		}
		urlTest := &URLTest{Adapter: outbound.NewAdapter(C.TypeURLTest, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil), group: group, logger: logger}
		manager.members[tag] = urlTest
		return urlTest
	}
	s.reserve = newGroup("reserve", mode, members(b, c), nil)
	s.main = newGroup("main", modeFastest, members(a), []adapter.Outbound{s.reserve})
	return s
}

// round is a round of the main group, the reserve with it, and the loss probes it started.
func (s *reserveStand) round(t *testing.T) {
	t.Helper()
	s.main.group.CheckOutbounds(context.Background(), true)
	s.waitProbes(t)
}

// waitProbes waits for the probes of the reserve, those before a switch too.
func (s *reserveStand) waitProbes(t *testing.T) {
	t.Helper()
	group := s.reserve.group
	require.Eventually(t, func() bool {
		running := group.lossRunning.Load() || group.updatePending.Load()
		group.switchProbes.Range(func(tag, _ any) bool {
			running = true
			return false
		})
		return !running
	}, 20*time.Second, 10*time.Millisecond)
}

// connect makes a connection through the main group, as the router does.
func (s *reserveStand) connect(t *testing.T) {
	t.Helper()
	conn, err := s.main.DialContext(sourceContext("10.0.0.1"), N.NetworkTCP, s.target)
	require.NoError(t, err)
	conn.Close()
}

// idleForTest makes the group one that was last used longer ago than its idle_timeout.
func (g *URLTestGroup) idleForTest() {
	g.lastUse.Store(time.Now().Add(-g.idleTimeout - time.Second))
}

// A fallback that is a group, in the mode loss or balance: while the outbounds of the group above
// answer it is tested with it, and selects, but no loss of its servers is probed, neither in the
// rounds nor before a switch. Once the outbounds are down and connections go through it, its
// servers are probed, until it has carried none for its idle_timeout.
func TestFallbackGroupProbedInUse(t *testing.T) {
	for _, mode := range []string{modeLoss, modeBalance} {
		t.Run(mode, func(t *testing.T) {
			s := newReserveStand(t, mode)
			reserve := s.reserve.group
			// idle: the rounds of the main group test the servers of the reserve
			for range 3 {
				s.round(t)
				s.connect(t)
			}
			require.Equal(t, "a", s.main.Now())
			require.NotNil(t, reserve.history.LoadURLTestHistory("b"))
			require.NotNil(t, reserve.history.LoadURLTestHistory("c"))
			require.False(t, reserve.inUse())
			s.loss.requireNoProbe(t, "the servers of an idle fallback were probed")
			// its choice goes by the URL tests, at once
			for _, fast := range []string{"c", "b"} {
				setResult(reserve, "b", 500)
				setResult(reserve, "c", 500)
				setResult(reserve, fast, 10)
				reserve.performUpdateCheck()
				require.Equal(t, fast, s.reserve.Now())
			}
			s.loss.requireNoProbe(t, "an idle fallback probed before a switch")

			// the main server dies: the first connection finds the reserve by the delays, and the
			// probes start
			s.mainDead.Store(true)
			_, err := s.main.DialContext(sourceContext("10.0.0.1"), N.NetworkTCP, s.target)
			require.Error(t, err)
			waitChoice(t, s.main.group, "reserve")
			s.connect(t)
			require.True(t, reserve.inUse())
			require.Eventually(t, func() bool {
				small, _ := s.loss.probes()
				return small >= 2
			}, 20*time.Second, 10*time.Millisecond, "the servers of a fallback in use were not probed")
			s.waitProbes(t)

			// in use, every round that is due probes
			s.loss.forget()
			s.round(t)
			small, _ := s.loss.probes()
			require.Equal(t, 2, small)

			// the main server is back, and connections go through it
			s.mainDead.Store(false)
			s.round(t)
			require.Equal(t, "a", s.main.Now())
			reserve.idleForTest()
			s.loss.forget()
			s.connect(t)
			s.round(t)
			require.False(t, reserve.inUse())
			s.loss.requireNoProbe(t, "the servers of a fallback that is idle again were probed")
		})
	}
}

// In use, the mode loss probes a server before it switches to it.
func TestFallbackGroupSwitchProbe(t *testing.T) {
	s := newReserveStand(t, modeLoss)
	reserve := s.reserve.group
	reserve.loss.interval = defaultLossInterval // one probe before a switch is enough for it
	s.round(t)
	setResult(reserve, "b", 10)
	setResult(reserve, "c", 500)
	reserve.performUpdateCheck()
	require.Equal(t, "b", s.reserve.Now())
	reserve.lossRunning.Store(true) // no periodic probe: the one before the switch is what is looked at
	reserve.used()
	setResult(reserve, "b", 500)
	setResult(reserve, "c", 10)
	reserve.performUpdateCheck()
	require.Equal(t, "b", s.reserve.Now(), "the member in use stays while the probe runs")
	waitChoice(t, reserve, "c")
	_, large := s.loss.probes()
	require.Equal(t, 1, large)
}

// What is a use: a connection dialed through the group or attached to it by the router. What is
// not: the dials of the tests of the group above and of the Clash API, which go through the group
// too. A group that was not started (it has no round yet) is used as any.
func TestGroupInUse(t *testing.T) {
	link, _ := testURL(t, 0)
	download := newDownloadServer(t, "full")
	loss := newLossProbeServer(t)
	a := newTestMember(C.TypeSOCKS, "a", dialProbe)
	newIdle := func() (*URLTest, *URLTestGroup) {
		urlTest, group := newTestURLTest(t, link, a)
		require.False(t, group.inUse())
		return urlTest, group
	}

	urlTest, group := newIdle()
	ctx := context.Background()
	_, err := urltest.URLTest(ctx, link, urlTest)
	require.NoError(t, err)
	_, _, err = urltest.DownloadTest(ctx, download.URL, urlTest)
	require.NoError(t, err)
	_, err = urltest.LossProbe(ctx, loss.URL, urltest.LossProbeSmall, urlTest)
	small, _ := loss.probes()
	require.Equal(t, 1, small, err)
	// hysteria2 and tuic: without a QUIC connection the probe ends after its first dial
	dials := a.dials.Load()
	_, err = urltest.LossProbeQUIC(ctx, loss.URL, urltest.LossProbeSmall, urlTest, quicTestMember{a})
	require.ErrorIs(t, err, urltest.ErrLossNotCounted)
	require.Greater(t, a.dials.Load(), dials)
	_, _ = urlTest.ListenPacket(urltest.ContextWithTest(ctx), M.ParseSocksaddr("127.0.0.1:53"))
	require.False(t, group.inUse(), "the dials of tests")

	conn, err := urlTest.DialContext(ctx, N.NetworkTCP, balanceTarget(t))
	require.NoError(t, err)
	conn.Close()
	require.True(t, group.inUse())
	group.idleForTest()
	require.False(t, group.inUse())
	conn, err = urlTest.DialContext(ctx, N.NetworkTCP, balanceTarget(t))
	require.NoError(t, err)
	conn.Close()
	require.True(t, group.inUse(), "in use again")

	urlTest, group = newIdle()
	_, _ = urlTest.ListenPacket(ctx, M.ParseSocksaddr("127.0.0.1:53"))
	require.True(t, group.inUse(), "a packet connection")

	urlTest, group = newIdle()
	one, other := net.Pipe()
	defer other.Close()
	detach := urlTest.AttachConnection(one)
	defer detach()
	require.True(t, group.inUse(), "a connection the router attaches")
}

// A group in use stays one when another takes its tag.
func TestTakeOverInUse(t *testing.T) {
	link, _ := testURL(t, 0)
	a := newTestMember(C.TypeSOCKS, "a", dialWorking)
	old, oldGroup := newTestURLTest(t, link, a)
	next, nextGroup := newTestURLTest(t, link, a)
	next.TakeOver(old)
	require.False(t, nextGroup.inUse())
	oldGroup.used()
	next.TakeOver(old)
	require.True(t, nextGroup.inUse())
}

// A fallback is chosen by its place in the list: the mode loss does not probe it before the
// switch, which would leave the connections on an outbound whose download stopped meanwhile.
func TestLossModeFallbackNotProbedBeforeSwitch(t *testing.T) {
	shortDownloadTimeout(t)
	full, frozen := newDownloadServer(t, "full"), newDownloadServer(t, "close")
	loss := newLossProbeServer(t)
	a, f := newTestMember(C.TypeSOCKS, "a", dialTo(frozen)), newTestMember(C.TypeSOCKS, "f", dialTo(full))
	_, group := newTestFallbackGroup(t, loss.URL, "", members(a), members(f), map[string]uint16{"a": 100, "f": 100})
	var err error
	group.mode, group.loss, err = groupMode(modeLoss, loss.URL, 0, 0, 0, 0)
	require.NoError(t, err)
	group.downloadLink = full.URL
	group.used()
	// a was taken frozen, as the last resort, and has passed a URL test since
	group.setFrozen("a", time.Now().Add(-time.Minute))
	tcp, _ := selectedTags(group)
	require.Equal(t, "a", tcp)
	group.performUpdateCheck()
	tcp, _ = selectedTags(group)
	require.Equal(t, "f", tcp, "a download through a stopped: the fallback at once")
	loss.requireNoProbe(t, "a fallback was probed before the switch to it")
}

package urltestgroup

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// restStand is a balance of five servers with delays 100 to 140, of which three are in it, with a
// download test. The server of the download test tells the member by the address it is reached at
// (each member has a listener of its own).
type restStand struct {
	urlTest *URLTest
	group   *URLTestGroup
	target  M.Socksaddr
	access  sync.Mutex
	tests   map[string]int
	stops   map[string]bool          // the members whose download stops
	hold    map[string]chan struct{} // the members whose download waits
}

func newRestStand(t *testing.T) *restStand {
	s := &restStand{target: balanceTarget(t), tests: make(map[string]int), stops: make(map[string]bool), hold: make(map[string]chan struct{})}
	var outbounds []adapter.Outbound
	delays := make(map[string]uint16)
	for i, tag := range []string{"a", "b", "c", "d", "e"} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.access.Lock()
			s.tests[tag]++
			stops, hold := s.stops[tag], s.hold[tag]
			s.access.Unlock()
			if hold != nil {
				select {
				case <-hold:
				case <-r.Context().Done():
					return
				}
			}
			w.Header().Set("Content-Length", fmt.Sprint(urltest.DownloadTestSize))
			if stops {
				w.Write(make([]byte, 16<<10))
				w.(http.Flusher).Flush()
				panic(http.ErrAbortHandler)
			}
			w.Write(make([]byte, urltest.DownloadTestSize))
		}))
		t.Cleanup(server.Close)
		address := server.Listener.Addr().String()
		outbounds = append(outbounds, newTestMember(C.TypeSOCKS, tag, func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
			if destination.Fqdn == "download.test" {
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}
			return dialWorking(ctx, network, destination)
		}))
		delays[tag] = uint16(100 + 10*i)
	}
	// with its first choice, download tested
	s.urlTest, s.group = newTestFallbackGroup(t, "", "http://download.test/", outbounds, nil, delays)
	t.Cleanup(func() { s.group.Close() })
	s.group.logger = formattingLogger(t)
	var err error
	// the loss URL refuses: the probes are not what is looked at
	s.group.mode, s.group.loss, err = groupMode(modeBalance, "http://127.0.0.1:1/loss", 0, 0, 0, 0)
	require.NoError(t, err)
	s.urlTest.mode, s.urlTest.loss = s.group.mode, s.group.loss
	s.group.balance.Store(newBalancer())
	s.group.performUpdateCheck()
	return s
}

func (s *restStand) tested() map[string]int {
	s.access.Lock()
	defer s.access.Unlock()
	tested := make(map[string]int)
	for tag, count := range s.tests {
		tested[tag] = count
	}
	return tested
}

func (s *restStand) connect(t *testing.T, source string) string {
	t.Helper()
	conn, err := s.urlTest.DialContext(sourceContext(source), N.NetworkTCP, s.target)
	require.NoError(t, err)
	conn.Close()
	balance := s.group.balance.Load()
	balance.access.Lock()
	defer balance.access.Unlock()
	device := balance.devices[source]
	require.NotNil(t, device, "the connection went by the plain choice")
	return device.member.Tag()
}

func (s *restStand) balance() []string {
	tags := make([]string, 0, 3)
	for _, member := range s.urlTest.Balance() {
		tags = append(tags, member.Tag)
	}
	return tags
}

// restLog keeps the lines of a logger.
type restLog struct {
	access sync.Mutex
	lines  strings.Builder
}

func (l *restLog) Write(p []byte) (int, error) {
	l.access.Lock()
	defer l.access.Unlock()
	return l.lines.Write(p)
}

func (l *restLog) count(text string) int {
	l.access.Lock()
	defer l.access.Unlock()
	return strings.Count(l.lines.String(), text)
}

// checked waits for the download tests that run.
func (s *restStand) checked(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool {
		if s.group.updatePending.Load() || !s.group.updateAccess.TryLock() {
			return false
		}
		s.group.updateAccess.Unlock()
		return true
	}, 20*time.Second, 5*time.Millisecond)
}

// Not in use, the balance rests: the delays change the best three at every selection, and nothing is
// download tested but the one choice, which stays; no connection is kept but the choice's.
func TestBalanceRests(t *testing.T) {
	s := newRestStand(t)
	for round := range 5 {
		for i, tag := range []string{"a", "b", "c", "d", "e"} {
			setResult(s.group, tag, uint16(100+10*((i+round)%5)))
		}
		s.group.performUpdateCheck()
		require.Nil(t, s.urlTest.Balance())
		require.Equal(t, "a", s.urlTest.Now())
	}
	require.Equal(t, map[string]int{"a": 1}, s.tested(), "the choice, before it was chosen")
	require.Equal(t, []string{"a"}, outboundReferences(t, s.urlTest))
	// a test of the group above dials the choice
	conn, err := s.urlTest.DialContext(urltest.ContextWithTest(context.Background()), N.NetworkTCP, s.target)
	require.NoError(t, err)
	conn.Close()
	require.Nil(t, s.urlTest.Balance())
	require.Empty(t, s.group.balance.Load().devices)
}

// The first connection after the group comes into use is spread, and so are those that come with it;
// the download tests of the members run then, but of the choice's, which passed its own lately.
func TestBalanceFirstConnection(t *testing.T) {
	s := newRestStand(t)
	best := s.group.balanceMembers(N.NetworkTCP, s.group.lossView(), nil)
	require.Len(t, best, 3)
	used := make(map[string]bool)
	for i := range 30 {
		source := fmt.Sprint("10.7.0.", i+1)
		member := s.connect(t, source)
		require.Equal(t, rendezvous(source, best).Tag(), member)
		used[member] = true
	}
	require.Equal(t, map[string]bool{"a": true, "b": true, "c": true}, used)
	require.Equal(t, []string{"a", "b", "c"}, s.balance())
	s.checked(t)
	require.Equal(t, map[string]int{"a": 1, "b": 1, "c": 1}, s.tested())
	require.Equal(t, []string{"a", "b", "c"}, s.balance())
	require.ElementsMatch(t, []string{"a", "b", "c"}, outboundReferences(t, s.urlTest))
	// and once: a selection tests no member again
	s.group.performUpdateCheck()
	require.Equal(t, map[string]int{"a": 1, "b": 1, "c": 1}, s.tested())
}

// The connections that come at once are all spread: none finds the group in use without its balance.
func TestBalanceFirstConnectionsAtOnce(t *testing.T) {
	for range 20 {
		s := newRestStand(t)
		best := s.group.balanceMembers(N.NetworkTCP, s.group.lossView(), nil)
		start := make(chan struct{})
		var waits sync.WaitGroup
		// selections meanwhile, which take the balance of an idle group away
		waits.Go(func() {
			<-start
			for range 20 {
				s.group.performUpdateCheck()
			}
		})
		for i := range 8 {
			waits.Go(func() {
				<-start
				source := fmt.Sprint("10.8.0.", i+1)
				conn, err := s.urlTest.DialContext(sourceContext(source), N.NetworkTCP, s.target)
				if err == nil {
					conn.Close()
				}
				balance := s.group.balance.Load()
				balance.access.Lock()
				device := balance.devices[source]
				balance.access.Unlock()
				if err != nil || device == nil || device.member != rendezvous(source, best) {
					t.Errorf("the connection of %s went by the plain choice (%v)", source, err)
				}
			})
		}
		close(start)
		waits.Wait()
		s.group.Close()
	}
}

// In use now and then: the balance rests between, and is the same again without a download test,
// until those it had are older than the loss_interval. A member that comes back into the balance of
// a group in use is not tested again either.
func TestBalanceInUseNowAndThen(t *testing.T) {
	s := newRestStand(t)
	output := new(restLog)
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now(), DisableColors: true}, output, "", nil, false)
	factory.SetLevel(log.LevelInfo)
	require.NoError(t, factory.Start())
	s.group.logger = factory.NewLogger("urltest")
	s.connect(t, "10.9.0.1")
	s.checked(t)
	tested := map[string]int{"a": 1, "b": 1, "c": 1}
	require.Equal(t, tested, s.tested())
	for range 3 {
		s.group.idleForTest()
		require.Nil(t, s.urlTest.Balance())
		require.Equal(t, []string{"a"}, outboundReferences(t, s.urlTest))
		s.group.performUpdateCheck()
		require.Nil(t, s.urlTest.Balance())
		require.Empty(t, s.group.balance.Load().tcp)
		s.connect(t, "10.9.0.1")
		require.Equal(t, []string{"a", "b", "c"}, s.balance())
		s.checked(t)
	}
	require.Equal(t, tested, s.tested())
	require.Equal(t, 1, output.count("balance over 3 outbounds: a, b, c"), "told once")

	// in use, d takes the place of c and gives it back
	setResult(s.group, "d", 105)
	s.group.performUpdateCheck()
	require.Equal(t, []string{"a", "d", "b"}, s.balance())
	setResult(s.group, "d", 130)
	s.group.performUpdateCheck()
	require.Equal(t, []string{"a", "b", "c"}, s.balance())
	tested["d"] = 1
	require.Equal(t, tested, s.tested())

	// the tests of b and c are due, a's is not
	for _, tag := range []string{"b", "c"} {
		s.group.history.StoreDownloadResult(tag, urltest.DownloadResult{At: time.Now().Add(-s.group.loss.interval - time.Second), Received: urltest.DownloadTestSize})
	}
	s.group.performUpdateCheck()
	require.Equal(t, tested, s.tested(), "they are in the balance")
	s.group.idleForTest()
	s.connect(t, "10.9.0.1")
	s.checked(t)
	tested["b"], tested["c"] = 2, 2
	require.Equal(t, tested, s.tested())
}

// A member that fails the download test after the group came into use leaves the balance, and its
// devices go to another; it was frozen before it is tested again.
func TestBalanceFirstConnectionFrozen(t *testing.T) {
	s := newRestStand(t)
	s.stops["b"] = true
	sources := make(map[string]string)
	for i := range 30 {
		source := fmt.Sprint("10.10.0.", i+1)
		sources[s.connect(t, source)] = source
	}
	s.checked(t)
	require.Equal(t, []string{"a", "c", "d"}, s.balance())
	require.Equal(t, map[string]int{"a": 1, "b": 1, "c": 1, "d": 1}, s.tested())
	if source, has := sources["b"]; has {
		require.NotEqual(t, "b", s.connect(t, source))
	}
	require.False(t, s.group.downloadPassed("b"))
	// a result stored by another group before it froze here does not pass it
	s.group.history.StoreDownloadResult("b", urltest.DownloadResult{At: time.Now(), Received: urltest.DownloadTestSize})
	require.False(t, s.group.downloadPassed("b"))
	// nor does one that stopped, though it was another group's and the member is not frozen here
	require.True(t, s.group.downloadPassed("c"))
	s.group.history.StoreDownloadResult("c", urltest.DownloadResult{At: time.Now(), Received: 16 << 10, Stopped: true})
	require.False(t, s.group.downloadPassed("c"))
	s.group.history.StoreDownloadResult("c", urltest.DownloadResult{At: time.Now(), Received: urltest.DownloadTestSize})
	s.stops["b"] = false
	setResult(s.group, "b", 110)
	s.group.performUpdateCheck()
	require.Equal(t, 2, s.tested()["b"])
	require.Equal(t, []string{"a", "b", "c"}, s.balance())
}

// Before a round has tested the members there is no balance: the first connections go by the plain
// choice, and the round's selection makes it.
func TestBalanceBeforeRound(t *testing.T) {
	s := newRestStand(t)
	s.group.roundDone.Store(false)
	conn, err := s.urlTest.DialContext(sourceContext("10.11.0.1"), N.NetworkTCP, s.target)
	require.NoError(t, err)
	conn.Close()
	require.Empty(t, s.group.balance.Load().devices)
	s.checked(t)
	require.NotNil(t, s.urlTest.Balance())
	require.Empty(t, s.balance(), "in use, and nothing in it")
	s.group.roundDone.Store(true)
	s.group.performUpdateCheck()
	require.Equal(t, []string{"a", "b", "c"}, s.balance())
	s.connect(t, "10.11.0.1")
}

// A group that is idle again before its download tests are done is at rest after them.
func TestBalanceIdleBeforeTested(t *testing.T) {
	s := newRestStand(t)
	s.group.lossRunning.Store(true) // no probes, whose ends ask for selections
	gate := make(chan struct{})
	s.hold["b"] = gate
	s.connect(t, "10.12.0.1")
	require.Eventually(t, func() bool { return s.tested()["b"] == 1 }, 10*time.Second, 5*time.Millisecond)
	s.group.idleForTest()
	close(gate)
	s.checked(t)
	require.Nil(t, s.urlTest.Balance())
	require.Empty(t, s.group.balance.Load().tcp)
}

// A hot swap: a balance in use goes on with the members not tested yet, which the new group tests;
// one at rest rests on, and is made at the first connection. A selection of the group that was
// replaced leaves the balance the other has.
func TestBalanceRestTakeOver(t *testing.T) {
	old, next := newRestStand(t), newRestStand(t)
	next.group.history = old.group.history
	swap := func() {
		// without e, and without c when it is in the balance
		next.group.outbounds = slices.DeleteFunc(slices.Clone(old.group.outbounds), func(member adapter.Outbound) bool {
			return member.Tag() == "e" || member.Tag() == "c" && old.group.inUse()
		})
		next.group.members = next.group.outbounds
		next.urlTest.TakeOver(old.urlTest)
	}
	gate := make(chan struct{})
	old.hold["b"] = gate
	old.connect(t, "10.13.0.1")
	require.Eventually(t, func() bool { return old.tested()["b"] == 1 }, 10*time.Second, 5*time.Millisecond)
	swap()
	require.True(t, next.group.inUse())
	require.Equal(t, []string{"a", "b"}, next.balance())
	balance := next.group.balance.Load()
	require.Len(t, balance.unchecked, 2)
	require.Contains(t, balance.devices, "10.13.0.1")
	close(gate)
	old.checked(t)
	require.Same(t, balance, next.group.balance.Load())
	require.Len(t, balance.unchecked, 2, "the old group's tests are not the new one's")
	next.group.performUpdateCheck()
	require.Empty(t, balance.unchecked)
	require.Equal(t, []string{"a", "b", "d"}, next.balance())

	old, next = newRestStand(t), newRestStand(t)
	next.group.history = old.group.history
	swap()
	require.False(t, next.group.inUse())
	require.Nil(t, next.urlTest.Balance())
	next.connect(t, "10.13.0.2")
	require.Equal(t, []string{"a", "b", "c"}, next.balance())
}

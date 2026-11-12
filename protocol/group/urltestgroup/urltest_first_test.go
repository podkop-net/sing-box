package urltestgroup

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// firstStand is a group of the servers a, b, ... with delays 100, 110, ... that was tested and is not
// in use yet.
type firstStand struct {
	urlTest *URLTest
	group   *URLTestGroup
	members map[string]*testMember
	server  *httptest.Server
	access  sync.Mutex
	order   []int64 // the sizes of the probes, as they came
	running int
	most    int
	hold    func(number int) chan struct{} // what the probe of this number waits for
}

func newFirstStand(t *testing.T, mode string, count int) *firstStand {
	s := &firstStand{members: make(map[string]*testMember)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var last int64
		fmt.Sscanf(r.Header.Get("Range"), "bytes=0-%d", &last)
		s.access.Lock()
		s.order = append(s.order, last+1)
		number := len(s.order)
		s.running++
		s.most = max(s.most, s.running)
		hold := s.hold
		s.access.Unlock()
		defer func() {
			s.access.Lock()
			s.running--
			s.access.Unlock()
		}()
		if hold != nil {
			if gate := hold(number); gate != nil {
				select {
				case <-gate:
				case <-r.Context().Done():
					return
				}
			}
		}
		// less than asked: at the window of a probe a megabyte takes seconds here
		const body = 32 << 10
		w.Header().Set("Content-Length", fmt.Sprint(body))
		w.Write(make([]byte, body))
	}))
	t.Cleanup(server.Close)
	s.server = server
	var outbounds []adapter.Outbound
	delays := make(map[string]uint16)
	for i := range count {
		tag := string(rune('a' + i))
		s.members[tag] = newTestMember(C.TypeSOCKS, tag, dialProbe)
		outbounds = append(outbounds, s.members[tag])
		delays[tag] = uint16(100 + 10*i)
	}
	s.urlTest, s.group = newModeGroup(t, mode, outbounds, delays, func(group *URLTestGroup) {
		group.tolerance = 5
	})
	s.group.loss.link = server.URL
	// tested, and not in use
	s.group.lastUse.Store(time.Time{})
	return s
}

func (s *firstStand) sizes() (small int, large int) {
	s.access.Lock()
	defer s.access.Unlock()
	for _, size := range s.order {
		switch size {
		case urltest.LossProbeSmall:
			small++
		case urltest.LossProbeLarge:
			large++
		}
	}
	return
}

func (s *firstStand) forget() {
	s.access.Lock()
	defer s.access.Unlock()
	s.order = nil
}

func (s *firstStand) connect(t *testing.T) {
	t.Helper()
	conn, err := s.urlTest.DialContext(sourceContext("10.0.0.1"), N.NetworkTCP, balanceTarget(t))
	require.NoError(t, err)
	conn.Close()
}

// settled waits for the probes that run.
func (s *firstStand) settled(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool {
		busy := s.group.lossRunning.Load() || s.group.updatePending.Load()
		s.group.switchProbes.Range(func(_, _ any) bool {
			busy = true
			return false
		})
		return !busy
	}, 20*time.Second, 10*time.Millisecond)
}

// A group that comes into use without counts probes the members it would probe once with the size
// that decides alone: the one in use and the three best others, in the balance those of the balance
// and two more, one after another. Nothing is made twice, at a round, or when the group comes into
// use again.
func TestFirstLossProbes(t *testing.T) {
	for mode, targets := range map[string]int{modeLoss: lossCandidates + 1, modeBalance: defaultBalanceSize + 2} {
		t.Run(mode, func(t *testing.T) {
			s := newFirstStand(t, mode, 8)
			s.connect(t)
			require.Eventually(t, func() bool {
				_, large := s.sizes()
				return large == targets
			}, 20*time.Second, 10*time.Millisecond)
			s.settled(t)
			small, large := s.sizes()
			require.Equal(t, [2]int{0, targets}, [2]int{small, large})
			require.Equal(t, 1, s.most, "one at a time")
			for i, member := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
				probed, _ := s.group.history.LossAttempt(member)
				require.Equal(t, i < targets, !probed.IsZero(), member)
			}
			// a round: nothing is due; idle and in use again, time after time: the same
			s.group.lossRound()
			for range 3 {
				s.group.idleForTest()
				s.connect(t)
			}
			s.settled(t)
			small, large = s.sizes()
			require.Equal(t, [2]int{0, targets}, [2]int{small, large})
		})
	}
}

// Due again, with the group in use again: a member that had a large probe within the loss_interval
// has a small one, whatever the large one counted.
func TestFirstLossProbeOnceAnInterval(t *testing.T) {
	s := newFirstStand(t, modeLoss, 2)
	s.connect(t)
	require.Eventually(t, func() bool {
		_, large := s.sizes()
		return large == 2
	}, 20*time.Second, 10*time.Millisecond)
	s.settled(t)
	_, known := s.group.history.LossOfWindow("a", time.Now(), lossMinSegments)
	require.False(t, known, "a few segments over the loopback decide nothing")
	due := func(large time.Duration) {
		for _, tag := range []string{"a", "b"} {
			// the large probe, and the last attempt, that long ago
			s.group.switchProbed.Store(tag, time.Now().Add(-large))
			s.group.history.StoreLossSample(tag, urltest.LossSample{At: time.Now().Add(-s.group.lossRest() - time.Second), Segments: 20})
		}
		s.group.idleForTest()
		s.forget()
		s.connect(t)
		require.Eventually(t, func() bool {
			small, large := s.sizes()
			return small+large == 2
		}, 20*time.Second, 10*time.Millisecond)
		s.settled(t)
	}
	due(s.group.lossRest() + 2*time.Second)
	small, large := s.sizes()
	require.Equal(t, [2]int{2, 0}, [2]int{small, large})
	// the large ones are older than the loss_interval
	due(s.group.loss.interval + time.Second)
	small, large = s.sizes()
	require.Equal(t, [2]int{0, 2}, [2]int{small, large})
}

// What makes a periodic probe a large one.
func TestLossProbeSize(t *testing.T) {
	s := newFirstStand(t, modeLoss, 1)
	group := s.group
	size := func() int64 { return group.lossProbeSize("a") }
	require.EqualValues(t, urltest.LossProbeSmall, size(), "never in use")
	group.usedSince.Store(time.Now())
	require.EqualValues(t, urltest.LossProbeLarge, size())
	group.usedSince.Store(time.Now().Add(-group.loss.interval))
	require.EqualValues(t, urltest.LossProbeSmall, size(), "in use for long")
	group.usedSince.Store(time.Now())
	storeLoss(group, "a", lossMinSegments-1, 5, 20*time.Millisecond)
	require.EqualValues(t, urltest.LossProbeLarge, size(), "a count too small to decide by")
	group.switchProbed.Store("a", time.Now())
	require.EqualValues(t, urltest.LossProbeLarge, size(), "given up for want of its turn")
	group.history.StoreLossFailure("a", time.Now())
	require.EqualValues(t, urltest.LossProbeSmall, size(), "had one")
	group.switchProbed.Delete("a")
	storeLoss(group, "a", 1, 0, 20*time.Millisecond)
	require.EqualValues(t, urltest.LossProbeSmall, size(), "a count to decide by")
	group.history.DeleteURLTestHistory("a")
	require.EqualValues(t, urltest.LossProbeLarge, size())
	group.history.StoreLossNotCounted("a", time.Now().Add(-lossNotCountedRest))
	require.EqualValues(t, urltest.LossProbeSmall, size(), "a member that could not be counted")

	// a hot swap: the use began when it did
	next, nextGroup := newTestURLTest(t, "", s.members["a"])
	group.usedSince.Store(time.Now().Add(-time.Minute))
	next.TakeOver(s.urlTest)
	require.Equal(t, group.usedSince.Load(), nextGroup.usedSince.Load())
}

// The choice follows each large probe, not the round of them.
func TestFirstLossProbeDecides(t *testing.T) {
	s := newFirstStand(t, modeLoss, 4)
	gate := make(chan struct{})
	defer close(gate)
	s.hold = func(number int) chan struct{} {
		if number < 3 {
			return nil
		}
		return gate
	}
	setResult(s.group, "b", 20)
	tcp, _ := selectedTags(s.group)
	require.Equal(t, "a", tcp)
	s.connect(t)
	waitChoice(t, s.group, "b")
	require.True(t, s.group.lossRunning.Load(), "the third probe is held")
}

// One before a switch that runs is the member's first: it is not made twice.
func TestFirstLossProbeRunsOnce(t *testing.T) {
	s := newFirstStand(t, modeLoss, 2)
	gate := make(chan struct{})
	s.hold = func(int) chan struct{} { return gate }
	s.group.used() // the first probe of a takes the turn
	require.Eventually(t, func() bool {
		_, large := s.sizes()
		return large == 1
	}, 10*time.Second, 10*time.Millisecond)
	_, running := s.group.switchProbes.Load("a")
	require.True(t, running, "a selection that would switch to a waits for it")
	started := time.Now()
	s.group.firstLossProbe("a", s.members["a"])
	require.Less(t, time.Since(started), 5*time.Second, "it waited for the turn the first one has")
	_, large := s.sizes()
	require.Equal(t, 1, large)
	close(gate)
	s.settled(t)
	_, large = s.sizes()
	require.Equal(t, 2, large)
}

// A group that is idle again in the middle of its probes makes no more of them.
func TestFirstLossProbesEndWithUse(t *testing.T) {
	s := newFirstStand(t, modeLoss, 4)
	gate := make(chan struct{})
	s.hold = func(int) chan struct{} { return gate }
	s.group.used()
	require.Eventually(t, func() bool {
		_, large := s.sizes()
		return large == 1
	}, 10*time.Second, 10*time.Millisecond)
	s.group.idleForTest()
	close(gate)
	s.settled(t)
	_, large := s.sizes()
	require.Equal(t, 1, large)
}

// A large probe cut by a change of the network says nothing and was none: the next one is large too.
func TestFirstLossProbeCut(t *testing.T) {
	s := newFirstStand(t, modeLoss, 1)
	s.group.lastUse.Store(time.Now())
	s.group.usedSince.Store(time.Now())
	gate := make(chan struct{})
	defer close(gate)
	s.hold = func(int) chan struct{} { return gate }
	done := make(chan struct{})
	go func() {
		s.group.firstLossProbe("a", s.members["a"])
		close(done)
	}()
	require.Eventually(t, func() bool {
		_, large := s.sizes()
		return large == 1
	}, 10*time.Second, 10*time.Millisecond)
	s.group.networkReset()
	s.server.CloseClientConnections()
	<-done
	attempt, _ := s.group.history.LossAttempt("a")
	require.True(t, attempt.IsZero())
	require.EqualValues(t, urltest.LossProbeLarge, s.group.lossProbeSize("a"))
	require.True(t, s.group.needsSwitchProbe("a"), "a switch to the member asks for one as well")
}

// Before a round has tested the members nothing is known of the best of them: the probes of a group
// that comes into use wait for its end.
func TestFirstLossProbesAfterRound(t *testing.T) {
	s := newFirstStand(t, modeLoss, 2)
	s.group.roundDone.Store(false)
	s.connect(t)
	s.settled(t)
	require.Empty(t, s.order)
	s.group.roundDone.Store(true)
	s.group.lossRound()
	require.Eventually(t, func() bool {
		_, large := s.sizes()
		return large == 2
	}, 10*time.Second, 10*time.Millisecond)
}

// idle_timeout of one interval, and a connection now and then: each connection that finds the group
// idle has a round at once, the ticker stops an interval or two after it, and the loss probes are made
// once.
func TestIdleTimeoutOfInterval(t *testing.T) {
	const interval = 300 * time.Millisecond
	s := newFirstStand(t, modeLoss, 2)
	link, tests := testURL(t, 0)
	s.group.links = linkList(link)
	s.group.interval, s.group.idleTimeout = interval, interval
	s.group.watchPause(&testPause{})
	s.group.PostStart()
	require.Eventually(t, func() bool { return tests.Load() == 2 }, 10*time.Second, time.Millisecond)
	ticking := func() bool {
		s.group.access.Lock()
		defer s.group.access.Unlock()
		return s.group.ticker != nil
	}
	time.Sleep(3 * interval)
	require.Equal(t, int32(2), tests.Load(), "no rounds without connections")
	for range 4 {
		before := tests.Load()
		s.connect(t)
		require.True(t, ticking())
		require.True(t, s.group.inUse())
		time.Sleep(4 * interval)
		require.False(t, ticking(), "the ticker stopped")
		require.False(t, s.group.inUse())
		rounds := (tests.Load() - before) / 2
		require.GreaterOrEqual(t, rounds, int32(1))
		require.LessOrEqual(t, rounds, int32(2))
	}
	s.settled(t)
	small, large := s.sizes()
	require.Equal(t, [2]int{0, 2}, [2]int{small, large})
	// connections that come more often than the interval keep the rounds coming
	before := tests.Load()
	for range 12 {
		s.connect(t)
		time.Sleep(interval / 2)
	}
	require.True(t, ticking())
	require.GreaterOrEqual(t, (tests.Load()-before)/2, int32(4))
}

// A connection of the router touches the group twice: as it is attached, and as it is dialed through
// the group. The group that was idle has its round at once all the same, and the loss probes after it,
// not an interval later.
func TestIdleGroupRoundAtFirstConnection(t *testing.T) {
	const interval = 20 * time.Second
	for range 5 {
		s := newFirstStand(t, modeLoss, 2)
		link, tests := testURL(t, 0)
		s.group.links = linkList(link)
		s.group.interval, s.group.idleTimeout = interval, interval
		s.group.watchPause(&testPause{})
		s.group.started.Store(true)
		idleSince := time.Now().Add(-2 * interval)
		s.group.lastActive.Store(idleSince)
		s.group.lastRound.Store(int64(idleSince.Sub(s.group.epoch)))
		for _, member := range s.members {
			s.group.history.StoreURLTestHistory(member.Tag(), &adapter.URLTestHistory{Time: idleSince, Delay: 100})
		}
		one, other := net.Pipe()
		detach := s.urlTest.AttachConnection(one)
		s.connect(t)
		require.Eventually(t, func() bool { return tests.Load() == 2 }, interval/4, 10*time.Millisecond, "a round at once")
		require.Eventually(t, func() bool {
			_, large := s.sizes()
			return large == 2
		}, interval/4, 10*time.Millisecond, "the loss probes after it")
		s.settled(t)
		require.EqualValues(t, 2, tests.Load(), "one round")
		detach()
		one.Close()
		other.Close()
	}
}

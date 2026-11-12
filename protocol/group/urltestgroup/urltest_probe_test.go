package urltestgroup

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// The tests of the package test their members many times a second: the spacing of tests
// through one first server is tested with a prober of its own.
func TestMain(m *testing.M) {
	probes = newProber(0)
	os.Exit(m.Run())
}

// chainMember is a member reached through the outbound detour (its dependency).
func chainMember(tag string, detour string, dial func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)) *testMember {
	return &testMember{Adapter: outbound.NewAdapter(C.TypeVLESS, tag, []string{N.NetworkTCP, N.NetworkUDP}, []string{detour}), dial: dial}
}

// Groups that ask for a test of one member with one URL at the same time get one test.
func TestProberSharesATest(t *testing.T) {
	p := newProber(0)
	release := make(chan struct{})
	member := newTestMember(C.TypeVLESS, "a", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		<-release
		return nil, errors.New("down")
	})
	var done sync.WaitGroup
	errs := make([]error, 5)
	for i := range errs {
		done.Add(1)
		go func() {
			defer done.Done()
			_, errs[i] = p.test(context.Background(), nil, "http://www.example.com/generate_204", member, nil)
		}()
	}
	require.Eventually(t, func() bool { return member.dials.Load() == 1 }, 2*time.Second, time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	close(release)
	done.Wait()
	require.Equal(t, int32(1), member.dials.Load())
	for _, err := range errs {
		require.Error(t, err)
	}
	// another URL is another test
	_, _ = p.test(context.Background(), nil, "http://www.example.org/generate_204", member, nil)
	require.Equal(t, int32(2), member.dials.Load())
}

// A test cut by the end of its group's round is not the result of the groups that waited for
// it: they test themselves.
func TestProberAbandonedTest(t *testing.T) {
	p := newProber(0)
	link, _ := testURL(t, 0)
	started := make(chan struct{})
	var first atomic.Bool
	member := newTestMember(C.TypeVLESS, "a", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if first.CompareAndSwap(false, true) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return dialWorking(ctx, network, destination)
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _, _ = p.test(ctx, nil, link, member, nil) }()
	<-started
	waited := make(chan error, 1)
	go func() {
		_, err := p.test(context.Background(), nil, link, member, nil)
		waited <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	require.NoError(t, <-waited)
	require.Equal(t, int32(2), member.dials.Load())
}

// Tests through one first server begin the spacing apart; through others, at once.
func TestProberSpacesAFirstHop(t *testing.T) {
	const spacing = 300 * time.Millisecond
	p := newProber(spacing)
	var access sync.Mutex
	starts := make(map[string][]time.Time)
	dial := func(name string) func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		return func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
			access.Lock()
			starts[name] = append(starts[name], time.Now())
			access.Unlock()
			return nil, errors.New("down")
		}
	}
	detour := newTestMember(C.TypeVLESS, "x", dial("x"))
	manager := &testOutboundManager{members: map[string]adapter.Outbound{"x": detour}}
	var chain []*testMember
	for _, tag := range []string{"a", "b", "c"} {
		chain = append(chain, chainMember(tag, "x", dial("via-x")))
	}
	alone := newTestMember(C.TypeVLESS, "d", dial("d"))
	slots := make(chan struct{}, 4)
	var done sync.WaitGroup
	for _, member := range append([]*testMember{alone}, chain...) {
		done.Add(1)
		go func() {
			defer done.Done()
			_, _ = p.test(context.Background(), manager, "http://www.example.com/generate_204", member, slots)
		}()
	}
	done.Wait()
	viaX := starts["via-x"]
	require.Len(t, viaX, 3)
	for i := 1; i < len(viaX); i++ {
		gap := viaX[i].Sub(viaX[i-1])
		require.GreaterOrEqual(t, gap, spacing-20*time.Millisecond, "tests through x %d and %d", i-1, i)
	}
	require.Len(t, starts["d"], 1)
	require.Less(t, starts["d"][0].Sub(viaX[0]).Abs(), spacing/2, "a test through another first server waits for none")
	require.Empty(t, starts["x"], "x itself was not tested")
}

func TestFirstHop(t *testing.T) {
	x := newTestMember(C.TypeVLESS, "x", dialRefused)
	a := chainMember("a", "x", dialRefused)
	b := chainMember("b", "a", dialRefused)
	lost := chainMember("lost", "endpoint", dialRefused)
	nested := &testGroup{testMember: newTestMember(C.TypeSelector, "group", dialRefused), member: x}
	viaGroup := chainMember("via-group", "group", dialRefused)
	manager := &testOutboundManager{members: map[string]adapter.Outbound{"x": x, "a": a, "b": b, "group": nested}}
	require.Equal(t, adapter.Outbound(x), firstHop(manager, x))
	require.Equal(t, adapter.Outbound(x), firstHop(manager, a))
	require.Equal(t, adapter.Outbound(x), firstHop(manager, b))
	require.Equal(t, "endpoint", firstHop(manager, lost))
	require.Equal(t, adapter.Outbound(nested), firstHop(manager, viaGroup))
	require.Equal(t, adapter.Outbound(a), firstHop(nil, a))
}

// The rounds take the URLs in turn by the clock, the others after the URL of the round in the
// order of the list; the median is of as many rounds as there are URLs.
func TestRoundPlan(t *testing.T) {
	links := []string{"https://a/", "https://b/", "https://c/"}
	base := time.Unix(1_800_000_000, 0).Truncate(time.Minute)
	var seen []string
	for i := range 4 {
		plan := roundPlan(links, time.Minute, base.Add(time.Duration(i)*time.Minute+time.Second))
		require.Equal(t, 3, plan.keep)
		require.Len(t, plan.links, 3)
		require.ElementsMatch(t, links, plan.links)
		seen = append(seen, plan.links[0])
		require.Equal(t, links[(indexOf(links, plan.links[0])+1)%3], plan.links[1])
		require.Equal(t, links[(indexOf(links, plan.links[0])+2)%3], plan.links[2])
	}
	require.Equal(t, seen[0], seen[3])
	require.ElementsMatch(t, links, seen[:3])
	// within one round the plan is the same whenever a group asks
	require.Equal(t, roundPlan(links, time.Minute, base.Add(time.Second)), roundPlan(links, time.Minute, base.Add(59*time.Second)))
	one := roundPlan([]string{"https://a/"}, time.Minute, base)
	require.Equal(t, []string{"https://a/"}, one.links)
	require.Equal(t, 1, one.keep)
	none := roundPlan(nil, time.Minute, base)
	require.Equal(t, []string{""}, none.links)
}

// The retry of a round takes the first URL after the one of the round that answered through
// the member last time, the next one when none did; the confirmation of a member whose
// connections fail takes the first that answered, from the URL of the round on.
func TestRetryAndConfirmLinks(t *testing.T) {
	history := urltest.NewHistoryStorage()
	plan := probePlan{links: []string{"https://a/", "https://b/", "https://c/", "https://d/"}, keep: 4}
	require.Equal(t, "https://b/", plan.retryLink(history, "m"), "nothing known: the next one")
	require.Equal(t, "https://a/", plan.confirmLink(history, "m"), "nothing known: the URL of the round")
	history.StoreURLTestLinkResult("m", "https://b/", false)
	history.StoreURLTestLinkResult("m", "https://c/", true)
	require.Equal(t, "https://c/", plan.retryLink(history, "m"))
	require.Equal(t, "https://c/", plan.confirmLink(history, "m"))
	require.Equal(t, "https://b/", plan.retryLink(history, "other"), "per member")
	history.StoreURLTestLinkResult("m", "https://c/", false)
	history.StoreURLTestLinkResult("m", "https://d/", false)
	require.Equal(t, "https://b/", plan.retryLink(history, "m"), "none answered: the next one")
	history.StoreURLTestLinkResult("m", "https://a/", true)
	require.Equal(t, "https://a/", plan.confirmLink(history, "m"))
	// a failure of the member keeps what is known of its URLs; its history going away does not
	history.StoreURLTestFailure("m", time.Now())
	_, known := history.URLTestLinkAnswered("m", "https://a/")
	require.True(t, known)
	history.DeleteURLTestHistory("m")
	_, known = history.URLTestLinkAnswered("m", "https://a/")
	require.False(t, known)
	require.Equal(t, "", probePlan{links: []string{"https://a/"}, keep: 1}.retryLink(history, "m"))

	// a minority of URLs that did not answer is passed over; most is judged as before
	five := probePlan{links: []string{"https://0/", "https://1/", "https://2/", "https://3/", "https://4/"}, keep: 5}
	history.StoreURLTestLinkResult("n", "https://1/", false)
	history.StoreURLTestLinkResult("n", "https://2/", true)
	history.StoreURLTestLinkResult("n", "https://3/", false)
	require.Equal(t, "https://2/", five.retryLink(history, "n"), "two of five failed")
	require.Equal(t, "https://2/", five.confirmLink(history, "n"))
	history.StoreURLTestLinkResult("n", "https://4/", false)
	require.Equal(t, "https://1/", five.retryLink(history, "n"), "three of five failed: the next one")
	require.Equal(t, "https://0/", five.confirmLink(history, "n"), "three of five failed: the URL of the round")
}

// A server that reaches no URL of two operators that are neighbours in the list (its hoster
// blocks both): with the next URL as the retry it was unavailable in one round of each cycle,
// and the group left it for that round. It costs the first round only, before anything is
// known of its URLs.
func TestNeighbourLinksDownCostTheFirstRoundOnly(t *testing.T) {
	var links []string
	for i := range 2 {
		links = append(links, fmt.Sprintf("http://127.0.0.1:1/blocked%d", i))
	}
	for range 3 {
		link, _ := testURL(t, 0)
		links = append(links, link)
	}
	member := newTestMember(C.TypeVLESS, "a", dialWorking)
	history := urltest.NewHistoryStorage()
	var unavailable []int
	for round := range 10 {
		plan := roundPlan(links, time.Minute, time.Unix(0, 0).Add(time.Duration(round)*time.Minute))
		result := urlTestOutbounds(context.Background(), nil, history, log.NewNOPFactory().Logger(), []adapter.Outbound{member}, plan, time.Minute, true, true, 1)
		if _, ok := result["a"]; !ok {
			unavailable = append(unavailable, round)
		}
	}
	require.Equal(t, []int{0}, unavailable)
	// a server that is down fails every URL: unavailable in every round, two tests a round
	dead := newTestMember(C.TypeVLESS, "dead", dialRefused)
	for round := range 5 {
		plan := roundPlan(links, time.Minute, time.Unix(0, 0).Add(time.Duration(round)*time.Minute))
		result := urlTestOutbounds(context.Background(), nil, history, log.NewNOPFactory().Logger(), []adapter.Outbound{dead}, plan, time.Minute, true, true, 1)
		require.NotContains(t, result, "dead")
		require.Equal(t, int32(2*(round+1)), dead.dials.Load(), "two tests a round")
	}
}

// A server that reaches only two URLs of five is judged as before the history of its URLs:
// unavailable in the rounds where the URL of the round and the next one do not answer.
func TestMostLinksDownIsJudgedAsBefore(t *testing.T) {
	var links []string
	for i := range 3 {
		links = append(links, fmt.Sprintf("http://127.0.0.1:1/blocked%d", i))
	}
	for range 2 {
		link, _ := testURL(t, 0)
		links = append(links, link)
	}
	member := newTestMember(C.TypeVLESS, "a", dialWorking)
	history := urltest.NewHistoryStorage()
	var unavailable []int
	for round := range 10 {
		plan := roundPlan(links, time.Minute, time.Unix(0, 0).Add(time.Duration(round)*time.Minute))
		result := urlTestOutbounds(context.Background(), nil, history, log.NewNOPFactory().Logger(), []adapter.Outbound{member}, plan, time.Minute, true, true, 1)
		if _, ok := result["a"]; !ok {
			unavailable = append(unavailable, round)
		}
	}
	require.Equal(t, []int{0, 1, 5, 6}, unavailable)
}

func indexOf(links []string, link string) int {
	for i, it := range links {
		if it == link {
			return i
		}
	}
	return -1
}

func TestURLTestSampleMedian(t *testing.T) {
	history := urltest.NewHistoryStorage()
	require.Equal(t, uint16(50), history.StoreURLTestSample("a", 10, 5, 50))
	require.Equal(t, uint16(55), history.StoreURLTestSample("a", 11, 5, 60))
	require.Equal(t, uint16(55), history.StoreURLTestSample("a", 12, 5, 55))
	// round 13 did not answer: no sample; one stray test moves the median a little only
	require.Equal(t, uint16(58), history.StoreURLTestSample("a", 14, 5, 2000))
	// a later test of the same round replaces its sample
	require.Equal(t, uint16(54), history.StoreURLTestSample("a", 14, 5, 52))
	// round 10 is out of the last five rounds
	require.Equal(t, uint16(58), history.StoreURLTestSample("a", 15, 5, 70))
	require.Len(t, history.LoadURLTestSamples("a"), 4)
	history.StoreURLTestFailure("a", time.Now())
	require.Empty(t, history.LoadURLTestSamples("a"))
	require.Equal(t, uint16(80), history.StoreURLTestSample("a", 16, 5, 80))
}

// A member that does not answer the URL of the round is tested with the next one: available
// when that one answers, with its delay as the sample; unavailable when it does not either.
func TestRoundRetriesTheNextLink(t *testing.T) {
	good, goodRequests := testURL(t, 0)
	bad := "http://127.0.0.1:1/generate_204"
	member := newTestMember(C.TypeVLESS, "a", dialWorking)
	history := urltest.NewHistoryStorage()
	plan := probePlan{links: []string{bad, good}, round: 7, keep: 2}
	result := urlTestOutbounds(context.Background(), nil, history, log.NewNOPFactory().Logger(), []adapter.Outbound{member}, plan, time.Minute, true, true, 1)
	require.Contains(t, result, "a")
	require.Equal(t, int32(1), goodRequests.Load())
	require.NotNil(t, history.LoadURLTestHistory("a"))
	require.Len(t, history.LoadURLTestSamples("a"), 1)
	_, failed := history.LoadURLTestFailure("a")
	require.False(t, failed)

	plan = probePlan{links: []string{bad, bad + "?again"}, round: 8, keep: 2}
	result = urlTestOutbounds(context.Background(), nil, history, log.NewNOPFactory().Logger(), []adapter.Outbound{member}, plan, time.Minute, true, true, 1)
	require.NotContains(t, result, "a")
	require.Nil(t, history.LoadURLTestHistory("a"))
	_, failed = history.LoadURLTestFailure("a")
	require.True(t, failed)
}

// A group with several URLs stores the median of its rounds as the delay of a member.
func TestURLTestGroupMedianOfRounds(t *testing.T) {
	fast, _ := testURL(t, 0)
	slow, _ := testURL(t, 120*time.Millisecond)
	member := newTestMember(C.TypeVLESS, "a", dialWorking)
	history := urltest.NewHistoryStorage()
	for round, link := range []string{slow, fast, fast} {
		plan := probePlan{links: []string{link}, round: int64(round), keep: 3}
		urlTestOutbounds(context.Background(), nil, history, log.NewNOPFactory().Logger(), []adapter.Outbound{member}, plan, time.Minute, true, true, 1)
	}
	delay := history.LoadURLTestHistory("a").Delay
	require.Less(t, delay, uint16(100), "the slow URL of one round is not the delay")
}

// urls of the options: in their order, without empty and repeated ones; url when none.
func TestURLTestLinksOption(t *testing.T) {
	require.Equal(t, []string{"https://a/", "https://b/"}, testLinks(option.URLTestOutboundOptions{URL: "https://c/", URLs: []string{"https://a/", "", "https://b/", "https://a/"}}))
	require.Equal(t, []string{"https://c/"}, testLinks(option.URLTestOutboundOptions{URL: "https://c/"}))
	require.Nil(t, testLinks(option.URLTestOutboundOptions{}))
	require.Error(t, checkTestLink("ftp://a/"))
	require.NoError(t, checkTestLink("https://cp.cloudflare.com/generate_204"))
}

// A test the Clash API asks for, with its own URL, leaves the median of the rounds alone; in a
// group of one URL it is stored as before.
func TestClientTestKeepsTheMedian(t *testing.T) {
	link, _ := testURL(t, 0)
	member := newTestMember(C.TypeVLESS, "a", dialWorking)
	history := urltest.NewHistoryStorage()
	history.StoreURLTestSample("a", 5, 3, 40)
	history.StoreURLTestHistory("a", &adapter.URLTestHistory{Time: time.Now(), Delay: 40})
	slow, _ := testURL(t, 150*time.Millisecond)
	result := URLTestOutbounds(context.Background(), nil, history, log.NewNOPFactory().Logger(), []adapter.Outbound{member}, slow, time.Minute, true, true)
	require.GreaterOrEqual(t, result["a"], uint16(150), "the client gets what it measured")
	require.Equal(t, uint16(40), history.LoadURLTestHistory("a").Delay)
	URLTestOutbounds(context.Background(), nil, history, log.NewNOPFactory().Logger(), []adapter.Outbound{member}, "http://127.0.0.1:1/", time.Minute, true, true)
	_, failed := history.LoadURLTestFailure("a")
	require.False(t, failed)

	single := urltest.NewHistoryStorage()
	single.StoreURLTestSample("a", 5, 1, 40)
	URLTestOutbounds(context.Background(), nil, single, log.NewNOPFactory().Logger(), []adapter.Outbound{member}, slow, time.Minute, true, true)
	require.GreaterOrEqual(t, single.LoadURLTestHistory("a").Delay, uint16(150))
	_ = link
}

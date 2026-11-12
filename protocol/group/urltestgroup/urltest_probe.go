package urltestgroup

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/option"
)

// hopSpacing is the least time between the starts of two URL tests whose connections go to
// the same first server (podkop-engine). An operator's DPI that freezes bursts of TLS hellos to
// one server counts them per server (2026-10-31, from two Russian access networks: a burst to
// one server froze it while a single hello to another passed). Hellos to one server one every
// 2 s passed 20 of 20, one every second 12 and 7 of 20. Tests through different first servers
// run at once.
const hopSpacing = 2 * time.Second

// probes is the URL tester of the process (podkop-engine). The groups of a configuration share
// their members (a server in the groups of several rules) and the first servers of the members
// (twenty servers of a subscription reached through one detour): each group testing on its
// own would test a server as many times as it has groups, at the same moment, and its rounds
// would open a TLS connection to the shared detour per member at once. Here a test of one
// outbound with one URL that another group asked for already is waited for, not run again,
// and tests through one first server begin hopSpacing apart.
var probes = newProber(hopSpacing)

type prober struct {
	spacing time.Duration
	access  sync.Mutex
	calls   map[probeKey]*probeCall
	// when the next test through a first server may begin
	hops map[any]time.Time
}

type probeKey struct {
	detour adapter.Outbound
	link   string
}

type probeCall struct {
	done  chan struct{}
	delay uint16
	err   error
	// the test was cut because the round of the group that ran it ended: the groups that
	// waited for it test themselves
	abandoned bool
}

func newProber(spacing time.Duration) *prober {
	return &prober{spacing: spacing, calls: make(map[probeKey]*probeCall), hops: make(map[any]time.Time)}
}

// test runs one URL test of detour with link, or waits for the one that runs. The outbounds
// are the configuration's own objects: two configurations (a reload, the tests) share none.
func (p *prober) test(ctx context.Context, manager adapter.OutboundManager, link string, detour adapter.Outbound, slots chan struct{}) (uint16, error) {
	key := probeKey{detour, link}
	for {
		p.access.Lock()
		call, running := p.calls[key]
		if !running {
			call = &probeCall{done: make(chan struct{})}
			p.calls[key] = call
			p.access.Unlock()
			call.delay, call.err = p.run(ctx, firstHop(manager, detour), link, detour, slots)
			call.abandoned = call.err != nil && roundEnded(ctx)
			p.access.Lock()
			delete(p.calls, key)
			p.access.Unlock()
			close(call.done)
			return call.delay, call.err
		}
		p.access.Unlock()
		select {
		case <-call.done:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
		if !call.abandoned {
			return call.delay, call.err
		}
	}
}

// run takes one of slots (nil: none), then waits until a test through hop may begin; while it
// waits it holds no slot, so that tests through other first servers go on.
func (p *prober) run(ctx context.Context, hop any, link string, detour adapter.Outbound, slots chan struct{}) (uint16, error) {
	for {
		if slots != nil {
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}
		wait := p.reserve(hop, time.Now())
		if wait == 0 {
			break
		}
		if slots != nil {
			<-slots
		}
		if err := sleepContext(ctx, wait); err != nil {
			return 0, err
		}
	}
	if slots != nil {
		defer func() { <-slots }()
	}
	return probeOutbound(ctx, link, detour)
}

// waitHop waits until a connection through hop may begin, and reserves it: for a test that
// takes no slot (the download test, the test of a member whose connections fail).
func (p *prober) waitHop(ctx context.Context, hop any) error {
	for {
		wait := p.reserve(hop, time.Now())
		if wait == 0 {
			return nil
		}
		if err := sleepContext(ctx, wait); err != nil {
			return err
		}
	}
}

// reserve gives hop to a test beginning at now and returns 0, or tells how long to wait.
func (p *prober) reserve(hop any, now time.Time) time.Duration {
	if p.spacing <= 0 {
		return 0
	}
	p.access.Lock()
	defer p.access.Unlock()
	if next, reserved := p.hops[hop]; reserved && now.Before(next) {
		return next.Sub(now)
	}
	if len(p.hops) > 1024 {
		for key, next := range p.hops {
			if !now.Before(next) {
				delete(p.hops, key)
			}
		}
	}
	p.hops[hop] = now.Add(p.spacing)
	return 0
}

func sleepContext(ctx context.Context, wait time.Duration) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// firstHop is the outbound whose server a connection through detour reaches first: detour, or
// the last of its chain of detours. A group in the chain ends it (which of its members a
// connection takes varies), and so does a detour the manager does not know (an endpoint).
func firstHop(manager adapter.OutboundManager, detour adapter.Outbound) any {
	current := detour
	for range 8 {
		if _, isGroup := current.(adapter.OutboundGroup); isGroup || manager == nil {
			break
		}
		dependencies := current.Dependencies()
		if len(dependencies) != 1 {
			break
		}
		next, loaded := manager.Outbound(dependencies[0])
		if !loaded {
			return dependencies[0]
		}
		current = next
	}
	return current
}

// probePlan is what a round tests its members with (podkop-engine).
type probePlan struct {
	// links are the URLs of the group from the one of the round on, in the order of the list:
	// links[0] is the URL of the round. A member that does not answer it is tested once more,
	// with retryLink: a member is unavailable when two URLs of the list do not answer through
	// it, not one (a server's hoster may block one of them)
	links []string
	round int64
	// keep is how many rounds the delay of a member is the median of
	// (urltest.HistoryStorage.StoreURLTestSample); 0: the delay stored is the one measured
	// (a test the Clash API asked for with its own URL)
	keep int
}

// roundPlan is the plan of the round that begins at now: the rounds are numbered by the clock
// (now divided by interval), so that the groups of the process test with the same URL in the
// same round, and the probes of one member by different groups are one.
func roundPlan(links []string, interval time.Duration, now time.Time) probePlan {
	if len(links) == 0 {
		return probePlan{links: []string{""}, keep: 1}
	}
	round := int64(0)
	if interval > 0 {
		round = now.UnixNano() / int64(interval)
	}
	first := int(round % int64(len(links)))
	plan := probePlan{links: make([]string, 0, len(links)), round: round, keep: len(links)}
	for i := range links {
		plan.links = append(plan.links, links[(first+i)%len(links)])
	}
	return plan
}

// retryLink is the URL a member that did not answer the URL of the round is tested with once
// more: the first of the others, from the URL of the round on, that answered through the
// member at its last test with it; the next one when none did or none is known (the first
// rounds, a member that was down), and when most URLs of the list did not answer through it
// at their last test (mostFailed). A server that does not reach two operators for good would
// otherwise fail the URL of the round and the next one in one round of each cycle where the
// two are neighbours in the list, and the group leave it for a round each time; a server that
// reaches few of them is judged as before. "" without a second URL.
func (p probePlan) retryLink(history *urltest.HistoryStorage, tag string) string {
	if len(p.links) < 2 {
		return ""
	}
	if !p.mostFailed(history, tag) {
		for _, link := range p.links[1:] {
			if answered, known := history.URLTestLinkAnswered(tag, link); known && answered {
				return link
			}
		}
	}
	return p.links[1]
}

// confirmLink is the URL of the one test that confirms a member whose connections fail: the
// first, from the URL of the round on, that answered through the member at its last test with
// it, the URL of the round when none did or when most did not (mostFailed). A URL the member's
// server cannot reach would otherwise call a working member down.
func (p probePlan) confirmLink(history *urltest.HistoryStorage, tag string) string {
	if !p.mostFailed(history, tag) {
		for _, link := range p.links {
			if answered, known := history.URLTestLinkAnswered(tag, link); known && answered {
				return link
			}
		}
	}
	return p.links[0]
}

// mostFailed tells whether more than half of the URLs of the plan did not answer through the
// member at their last test with it: a minority of URLs its server cannot reach is passed
// over (retryLink, confirmLink), more is no longer a block of some operators but a server that
// works badly, or one that was down.
func (p probePlan) mostFailed(history *urltest.HistoryStorage, tag string) bool {
	failed := 0
	for _, link := range p.links {
		if answered, known := history.URLTestLinkAnswered(tag, link); known && !answered {
			failed++
		}
	}
	return 2*failed > len(p.links)
}

// testLinks are the URLs of the tests of a group: urls, or url, without empty and repeated ones;
// none for the default (urltest.URLTest).
func testLinks(options option.URLTestOutboundOptions) []string {
	var links []string
	for _, link := range options.URLs {
		if link != "" && !slices.Contains(links, link) {
			links = append(links, link)
		}
	}
	if len(links) == 0 {
		return linkList(options.URL)
	}
	return links
}

func linkList(link string) []string {
	if link == "" {
		return nil
	}
	return []string{link}
}

// checkTestLink tells whether a URL test can use link.
func checkTestLink(link string) error {
	return checkDownloadLink("urls", link)
}

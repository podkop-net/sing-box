package dns

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

// The DNS server of the type group (podkop-engine) asks other DNS servers of the box, its
// members, one after another: in the order of the list ("order", the default), or the
// fastest first ("fastest"). podkop lets the user list several DNS servers this way; the
// rules, final and default_domain_resolver point to the group.
//
// Candidates. "order": the members in the order of the list. "fastest": by the smoothed
// time of their answers (an EWMA of the answered queries, a new one weighing 1/4), those
// not measured yet after the measured ones, in the order of the list.
//
// Answers. NOERROR and NXDOMAIN are answers: the time is recorded and the member counts as
// answering. Any other rcode (SERVFAIL, REFUSED, ...) is usually about the name or a
// policy, not about the member: the next candidate is asked and nothing is counted, and
// when nobody gives an answer, the first such reply is returned. An error or a timeout is
// a failure and the next candidate is asked. A caller that gave the query up gets its
// error at once and nothing is counted.
//
// Timeout of an attempt, before the next candidate is asked: 4 times the member's smoothed
// time, at least 1.5 s and at most 3 s; 3 s when it is not measured. 4 times, as a TCP
// retransmission timeout is the smoothed time plus 4 deviations: with no deviation kept, it
// covers the spread between the answers a server has at hand and those it must resolve. At
// least 1.5 s: a lost datagram of plain DNS is sent again after 1 s (exchange_fresh.go) and
// a lost SYN of DoT or DoH after 1 s as well; both still get their answer before the group
// moves on, so that one lost packet is no failure. At most 3 s, as the provider fallback
// gives its servers: two dead members still leave the third 4 s of the 10 s of a query. The
// last step has no timeout of its own, only the caller's deadline: the last candidate, or,
// when the provider safety net follows, the net. The caller's deadline always wins; a member
// cut by it before its time counts nothing.
//
// Together after a timeout. A member that gives no answer in its time tells that the way to it
// may be dead (an uplink down, DoH blocked on the way), and then the members after it often are
// as well: asked one after another, four of them take 12 s, more than the 10 s of a query (on a
// router whose DoH servers were all dropped, the first two queries got no answer). So when a
// member times out and more than one candidate is left, those are asked at once, each within
// its timeout (none of its own when no safety net follows: together they are the last step),
// and the first answer is taken; the others are cut and count nothing. A reply with another
// rcode or an error that comes in time moves on to the next candidate as before. A group whose
// members answer never asks together; while a dead first member is not set aside yet (two
// queries), each of those queries costs one copy for each member left.
//
// Set aside. A member that fails twice in a row is set aside, as a server of the fallback
// is: queries that fail together (a closed connection they shared, a dead server they
// waited for) count once, a second failure counting only for a query started after the
// first was counted. A member set aside is skipped while another one is healthy, and a copy
// of one query is sent to it in the background, 30 s after it was set aside at first, then
// doubling up to every 5 minutes; the first answer (NOERROR or NXDOMAIN) brings it back, and
// in "order" it is first again at once. When every member is set aside, all are asked in
// order, as if healthy; with the safety net (below) the provider is asked first instead and
// the members are probed, as the fallback answers from the provider while its server is set
// aside: asking every dead member first would cost each query their timeouts. Only when the
// provider fails too are the members asked in order.
//
// Measurements. In "fastest", when a member's measurement is older than a minute (or
// missing), a copy of a query another member answered is sent to it in the background: one
// copy per query at most, one in flight per member; a member that did not answer the copy
// gets the next one a minute later, so that one which keeps failing or refusing is not sent
// a copy of every query. The copies and probes never delay or change the reply; they end
// with the timeout of an attempt or the close of the group, which waits for them.
//
// Safety net. When the provider DNS fallback is enabled (SING_BOX_DNS_FALLBACK), no member
// is a provider DNS server and one member at least would have the fallback alone (a plain
// socket to a public address or name, see fallbackExclusion), a query that every member
// failed with an error (no rcode at all) is asked of the provider's servers, as the
// fallback asks them; their answer lives 60 s at most. So a list of local or private
// resolvers (a filter in the LAN, a server behind a VPN) never sends its queries to the
// provider, as one of them alone would not. It is decided when the box starts, as the
// outbounds a detour names exist only then. The members have no fallback of their own: the
// group decides whom to ask (client_fallback.go).
//
// A network reset clears the failures, the set-aside state and the measurements: they
// belong to the network sing-box has just left. Results of queries sent before it count
// nothing. Changes of state are written at the warn level, as the fallback does, also when
// a query of sing-box itself caused them (stateContext); single queries at the debug level.

const (
	groupAttemptFactor = 4
	groupAttemptMin    = 1500 * time.Millisecond
	groupAttemptMax    = 3 * time.Second
	groupStaleAfter    = time.Minute
	groupSmoothing     = 4 // a new time weighs 1/groupSmoothing in the smoothed one
)

// groupTiming are the times of a group, apart so that tests can shorten them.
type groupTiming struct {
	attemptMin time.Duration
	attemptMax time.Duration // also the timeout of a member not measured
	probeFirst time.Duration
	probeMax   time.Duration
	staleAfter time.Duration
}

var defaultGroupTiming = groupTiming{
	attemptMin: groupAttemptMin,
	attemptMax: groupAttemptMax,
	probeFirst: fallbackProbeFirst,
	probeMax:   fallbackProbeMax,
	staleAfter: groupStaleAfter,
}

var errGroupSetAside = E.New("every server is set aside")

func RegisterGroupTransport(registry *TransportRegistry) {
	RegisterTransport[option.GroupDNSServerOptions](registry, C.DNSTypeGroup, NewGroupTransport)
}

var _ adapter.DNSGroupTransport = (*GroupTransport)(nil)

type GroupTransport struct {
	TransportAdapter
	ctx        context.Context
	logger     logger.ContextLogger
	strategy   string
	tags       []string
	timing     groupTiming
	netEnabled bool // the provider DNS fallback is enabled

	access     sync.Mutex
	members    []*groupMember  // nil until they are found (resolveMembers)
	netDecided bool            // decideNet ran
	net        *fallbackServer // the safety net, nil when there is none
	netInUse   bool            // the last query no member answered was answered by the net
	netAnswer  time.Time
	answerSeq  uint64 // answers of the members, to tell a late answer of the net (netAnswered)
	epoch      uint64 // network resets
	closed     bool
	closing    context.Context // ends the background exchanges
	cancel     context.CancelFunc
	tasks      sync.WaitGroup // the background exchanges
}

type groupMember struct {
	tag       string
	transport adapter.DNSTransport

	// under the lock of the group
	failures    int       // in a row
	countedAt   time.Time // the last failure counted, or the last network reset
	down        bool      // set aside
	probeAt     time.Time
	probeEvery  time.Duration
	probing     bool // a probe in flight
	refreshing  bool // a copy of "fastest" in flight
	refreshAt   time.Time
	smoothed    time.Duration // 0: not measured
	measuredAt  time.Time
	lastAnswer  time.Time
	answers     uint64
	failedTotal uint64
}

func NewGroupTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.GroupDNSServerOptions) (adapter.DNSTransport, error) {
	return newGroupTransport(ctx, logger, tag, options, fallbackEnabled)
}

func newGroupTransport(ctx context.Context, logger logger.ContextLogger, tag string, options option.GroupDNSServerOptions, netEnabled bool) (*GroupTransport, error) {
	strategy := options.Strategy
	switch strategy {
	case "":
		strategy = C.DNSGroupStrategyOrder
	case C.DNSGroupStrategyOrder, C.DNSGroupStrategyFastest:
	default:
		return nil, E.New("unknown strategy of group ", tag, ": ", strategy)
	}
	if len(options.Servers) == 0 {
		return nil, E.New("missing servers of group ", tag)
	}
	seen := make(map[string]bool, len(options.Servers))
	for _, server := range options.Servers {
		switch {
		case server == "":
			return nil, E.New("empty server tag in group ", tag)
		case server == tag:
			return nil, E.New("group ", tag, " lists itself")
		case seen[server]:
			return nil, E.New("duplicate server ", server, " in group ", tag)
		}
		seen[server] = true
	}
	tags := slices.Clone([]string(options.Servers))
	closing, cancel := context.WithCancel(context.Background())
	return &GroupTransport{
		// the members are its dependencies: they start first, and they are referenced (they
		// keep their idle connections) while the group is
		TransportAdapter: NewTransportAdapter(C.DNSTypeGroup, tag, tags),
		ctx:              ctx,
		logger:           logger,
		strategy:         strategy,
		tags:             tags,
		timing:           defaultGroupTiming,
		netEnabled:       netEnabled,
		closing:          closing,
		cancel:           cancel,
	}, nil
}

// initializeGroups lets the groups find their members, once every DNS server of the box
// exists: the DNS router calls it when it is initialized, so that a wrong member fails the
// configuration check, not only the start.
func initializeGroups(manager adapter.DNSTransportManager) error {
	if manager == nil {
		return nil
	}
	for _, transport := range manager.Transports() {
		if group, isGroup := transport.(*GroupTransport); isGroup {
			err := group.resolveMembers(manager)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// resolveMembers finds the members by tag, once.
func (g *GroupTransport) resolveMembers(manager adapter.DNSTransportManager) error {
	g.access.Lock()
	resolved := g.members != nil
	g.access.Unlock()
	if resolved {
		return nil
	}
	if manager == nil {
		return E.New("missing DNS transport manager")
	}
	members := make([]*groupMember, 0, len(g.tags))
	for _, tag := range g.tags {
		transport, loaded := manager.Transport(tag)
		if !loaded {
			return E.New("server ", tag, " of group ", g.Tag(), " not found")
		}
		switch transport.Type() {
		case C.DNSTypeGroup:
			return E.New("server ", tag, " of group ", g.Tag(), " is a group: groups do not nest")
		case C.DNSTypeFakeIP, C.DNSTypeHosts:
			// their answers are not those of the internet: a fake address, NXDOMAIN for any
			// name not listed
			return E.New("server ", tag, " of group ", g.Tag(), " is of the type ", transport.Type(), ", which cannot be in a group")
		}
		members = append(members, &groupMember{tag: tag, transport: transport})
	}
	g.access.Lock()
	if g.members != nil {
		g.access.Unlock()
		return nil
	}
	g.members = members
	g.access.Unlock()
	for _, member := range members {
		if state := fallbackStateOf(member.transport); state != nil {
			state.grouped.Store(true)
			g.logger.Warn("no provider DNS fallback for server ", member.tag, ": member of group ", g.Tag())
		}
	}
	return nil
}

// decideNet decides once whether the group has the safety net, once its members are found:
// when the box starts, or at the first query of a group that was not started.
func (g *GroupTransport) decideNet() error {
	g.access.Lock()
	if !g.netEnabled || g.netDecided || g.members == nil {
		g.access.Unlock()
		return nil
	}
	g.netDecided = true
	var (
		provider string
		reasons  []string
		eligible bool
	)
	for _, member := range g.members {
		if member.transport.Type() == C.DNSTypeProvider {
			provider = member.tag
			break
		}
		if state := fallbackStateOf(member.transport); state == nil {
			reasons = append(reasons, member.tag+": type "+member.transport.Type())
		} else if reason := fallbackExclusion(g.ctx, state.options); reason != "" {
			reasons = append(reasons, member.tag+": "+reason)
		} else {
			eligible = true
		}
	}
	var err error
	if provider == "" && eligible {
		// under the lock: a query planned meanwhile would miss the net; nothing here calls
		// the group
		g.net, err = newProviderAsker(g.ctx)
	}
	net := g.net
	g.access.Unlock()
	switch {
	case err != nil:
		return E.Cause(err, "provider DNS of group ", g.Tag())
	case provider != "":
		g.logger.Warn("no provider DNS fallback for group ", g.Tag(), ": its server ", provider, " is the provider")
	case net == nil:
		g.logger.Warn("no provider DNS fallback for group ", g.Tag(), ": none of its servers would have it alone (", strings.Join(reasons, "; "), ")")
	default:
		g.logger.Warn("group ", g.Tag(), " falls back to provider DNS when every server fails")
	}
	return nil
}

func (g *GroupTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		// found already when the DNS router was initialized, unless the group was created
		// otherwise
		err := g.resolveMembers(service.FromContext[adapter.DNSTransportManager](g.ctx))
		if err != nil {
			return err
		}
		return g.decideNet()
	case adapter.StartStateStart:
		scope.Add(g.close)
	}
	return nil
}

// close ends the background exchanges and waits for them; no new one starts after it.
func (g *GroupTransport) close() error {
	g.access.Lock()
	g.closed = true
	g.access.Unlock()
	g.cancel()
	g.tasks.Wait()
	return nil
}

// Reset starts over on a new network: the members' own connections are reset by the DNS
// router, which resets every server.
func (g *GroupTransport) Reset() {
	g.access.Lock()
	g.epoch++
	now := time.Now()
	var back []string
	for _, member := range g.members {
		if member.down {
			back = append(back, member.tag)
		}
		member.failures, member.countedAt, member.down = 0, now, false
		member.probeAt, member.probeEvery = time.Time{}, 0
		member.smoothed, member.measuredAt, member.refreshAt = 0, time.Time{}, time.Time{}
	}
	g.netInUse = false
	g.access.Unlock()
	if len(back) > 0 {
		g.logger.Warn("network reset: servers set aside are asked again: ", strings.Join(back, ", "))
	}
}

// groupAttempt is an exchange with a member with its timeout.
type groupAttempt struct {
	member  *groupMember
	timeout time.Duration
}

type groupPlan struct {
	epoch    uint64
	answers  uint64 // answerSeq when it was made
	attempts []groupAttempt
	net      *fallbackServer
	netFirst bool // every member is set aside: the net is asked before them
}

func (g *GroupTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	plan, err := g.plan(ctx, message)
	if err != nil {
		return nil, err
	}
	if plan.netFirst {
		response, err := plan.net.exchangeProvider(ctx, g.ctx, g.logger, message)
		if err == nil {
			g.netAnswered(ctx, plan, errGroupSetAside)
			return response, nil
		}
		if ctx.Err() != nil {
			return nil, err
		}
		g.logger.DebugContext(ctx, "provider DNS failed (", err, "), asking the servers set aside")
		plan.net = nil // asked already: the last member is the last step
	}
	var (
		rcodeReply *mDNS.Msg
		lastErr    error
		tried      []*groupMember
	)
	for index, attempt := range plan.attempts {
		member := attempt.member
		attemptCtx, cancel := ctx, context.CancelFunc(func() {})
		if index < len(plan.attempts)-1 || plan.net != nil {
			attemptCtx, cancel = context.WithTimeout(ctx, attempt.timeout)
		}
		startAt := time.Now()
		response, err := member.transport.Exchange(attemptCtx, message)
		elapsed := time.Since(startAt)
		cancel()
		response, err = groupResult(message, response, err)
		if err == nil && isGroupAnswer(response) {
			g.answered(ctx, member, plan.epoch, elapsed)
			g.refresh(ctx, plan.epoch, member, tried, message)
			return response, nil
		}
		tried = append(tried, member)
		if err == nil {
			if rcodeReply == nil {
				rcodeReply = response
			}
			if ctx.Err() != nil {
				break
			}
			g.logger.DebugContext(ctx, "server ", member.tag, " replied ", mDNS.RcodeToString[response.Rcode], ", asking the next one")
			continue
		}
		if ctx.Err() != nil {
			// the caller gave the query up, or its deadline came: that counts only when the
			// member had all of its time
			if errors.Is(ctx.Err(), context.DeadlineExceeded) && elapsed >= attempt.timeout {
				g.failed(ctx, member, plan.epoch, startAt, err)
			}
			if rcodeReply != nil {
				return rcodeReply, nil
			}
			return nil, err
		}
		g.failed(ctx, member, plan.epoch, startAt, err)
		lastErr = E.Cause(err, "server ", member.tag)
		g.logger.DebugContext(ctx, "server ", member.tag, " failed: ", err)
		if rest := plan.attempts[index+1:]; len(rest) > 1 && elapsed >= attempt.timeout {
			g.logger.DebugContext(ctx, "server ", member.tag, " gave no answer in ", attempt.timeout, ", asking the other ", len(rest), " together")
			response, reply, err := g.exchangeTogether(ctx, plan, rest, message, tried)
			if response != nil {
				return response, nil
			}
			if rcodeReply == nil {
				rcodeReply = reply
			}
			if err != nil {
				lastErr = err
			}
			if ctx.Err() != nil {
				if rcodeReply != nil {
					return rcodeReply, nil
				}
				return nil, lastErr
			}
			break
		}
	}
	if rcodeReply != nil {
		return rcodeReply, nil
	}
	if lastErr == nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, E.New("no server of group ", g.Tag(), " to ask")
	}
	if plan.net != nil && ctx.Err() == nil {
		response, err := plan.net.exchangeProvider(ctx, g.ctx, g.logger, message)
		if err == nil {
			g.netAnswered(ctx, plan, lastErr)
			return response, nil
		}
		g.logger.DebugContext(ctx, "provider DNS failed as well: ", err)
	}
	return nil, lastErr
}

// exchangeTogether asks the members of attempts at once, after one before them gave no answer in
// its time. It returns the first answer (NOERROR or NXDOMAIN), or else the first reply of
// another rcode and the error of the last member that failed. A member cut by the answer of
// another, or by the caller before its time, counts nothing.
func (g *GroupTransport) exchangeTogether(ctx context.Context, plan groupPlan, attempts []groupAttempt, message *mDNS.Msg, tried []*groupMember) (*mDNS.Msg, *mDNS.Msg, error) {
	togetherCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type outcome struct {
		attempt  groupAttempt
		response *mDNS.Msg
		err      error
		startAt  time.Time
		elapsed  time.Duration
	}
	outcomes := make(chan outcome, len(attempts))
	for _, attempt := range attempts {
		// a copy each: a transport may change the message it sends (its ID)
		go func(attempt groupAttempt, message *mDNS.Msg) {
			attemptCtx, attemptCancel := togetherCtx, context.CancelFunc(func() {})
			if plan.net != nil {
				attemptCtx, attemptCancel = context.WithTimeout(togetherCtx, attempt.timeout)
			}
			startAt := time.Now()
			response, err := attempt.member.transport.Exchange(attemptCtx, message)
			elapsed := time.Since(startAt)
			attemptCancel()
			response, err = groupResult(message, response, err)
			outcomes <- outcome{attempt, response, err, startAt, elapsed}
		}(attempt, message.Copy())
	}
	var (
		rcodeReply *mDNS.Msg
		lastErr    error
	)
	for range attempts {
		result := <-outcomes
		member := result.attempt.member
		switch {
		case result.err == nil && isGroupAnswer(result.response):
			g.answered(ctx, member, plan.epoch, result.elapsed)
			g.refresh(ctx, plan.epoch, member, tried, message)
			return result.response, nil, nil
		case result.err == nil:
			tried = append(tried, member)
			if rcodeReply == nil {
				rcodeReply = result.response
			}
			g.logger.DebugContext(ctx, "server ", member.tag, " replied ", mDNS.RcodeToString[result.response.Rcode])
		case ctx.Err() != nil:
			// as one after another: only a member that had all of its time failed
			if errors.Is(ctx.Err(), context.DeadlineExceeded) && result.elapsed >= result.attempt.timeout {
				g.failed(ctx, member, plan.epoch, result.startAt, result.err)
			}
			lastErr = result.err
		default:
			tried = append(tried, member)
			g.failed(ctx, member, plan.epoch, result.startAt, result.err)
			lastErr = E.Cause(result.err, "server ", member.tag)
			g.logger.DebugContext(ctx, "server ", member.tag, " failed: ", result.err)
		}
	}
	return nil, rcodeReply, lastErr
}

// ExchangeAsync must not keep the caller, which reads the next queries of its client.
func (g *GroupTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		callback(g.Exchange(ctx, message))
	}()
}

// plan chooses the candidates of a query and sends the probes that are due.
func (g *GroupTransport) plan(ctx context.Context, message *mDNS.Msg) (groupPlan, error) {
	err := g.decideNet()
	if err != nil {
		return groupPlan{}, err
	}
	g.access.Lock()
	if g.members == nil {
		g.access.Unlock()
		return groupPlan{}, E.New("group ", g.Tag(), " has not found its servers")
	}
	plan := groupPlan{epoch: g.epoch, answers: g.answerSeq, net: g.net}
	candidates := make([]*groupMember, 0, len(g.members))
	for _, member := range g.members {
		if !member.down {
			candidates = append(candidates, member)
		}
	}
	var probes []groupAttempt
	if len(candidates) == 0 {
		// every member is set aside: all are asked in order, and the first to answer is back;
		// with the safety net they are asked only when the provider fails
		candidates = append(candidates, g.members...)
		plan.netFirst = g.net != nil
	} else if g.strategy == C.DNSGroupStrategyFastest {
		slices.SortStableFunc(candidates, func(left *groupMember, right *groupMember) int {
			switch {
			case left.smoothed == 0 || right.smoothed == 0:
				return cmp.Compare(right.smoothed, left.smoothed) // the measured first
			default:
				return cmp.Compare(left.smoothed, right.smoothed)
			}
		})
	}
	// the members set aside that are not asked now are probed
	if len(candidates) < len(g.members) || plan.netFirst {
		now := time.Now()
		for _, member := range g.members {
			if !g.closed && member.down && !member.probing && !now.Before(member.probeAt) {
				member.probing = true
				member.probeAt = now.Add(member.probeEvery)
				member.probeEvery = min(member.probeEvery*2, g.timing.probeMax)
				g.tasks.Add(1)
				probes = append(probes, groupAttempt{member, g.attemptTimeout(member)})
			}
		}
	}
	for _, member := range candidates {
		plan.attempts = append(plan.attempts, groupAttempt{member, g.attemptTimeout(member)})
	}
	g.access.Unlock()
	for _, probe := range probes {
		g.background(ctx, probe, message.Copy(), plan.epoch, true)
	}
	return plan, nil
}

// attemptTimeout: under the lock.
func (g *GroupTransport) attemptTimeout(member *groupMember) time.Duration {
	if member.smoothed == 0 {
		return g.timing.attemptMax
	}
	return min(max(member.smoothed*groupAttemptFactor, g.timing.attemptMin), g.timing.attemptMax)
}

// refresh sends, in "fastest", a copy of a query the answerer answered to the healthy member
// whose measurement is the oldest, when it is older than staleAfter or missing.
func (g *GroupTransport) refresh(ctx context.Context, epoch uint64, answerer *groupMember, tried []*groupMember, message *mDNS.Msg) {
	if g.strategy != C.DNSGroupStrategyFastest {
		return
	}
	g.access.Lock()
	if g.closed || epoch != g.epoch {
		g.access.Unlock()
		return
	}
	now := time.Now()
	var (
		stale     *groupMember
		staleTime time.Time
	)
	for _, member := range g.members {
		if member == answerer || member.down || member.refreshing || slices.Contains(tried, member) {
			continue
		}
		// a copy that got no answer counts as a measurement for the time between copies
		last := member.measuredAt
		if member.refreshAt.After(last) {
			last = member.refreshAt
		}
		if !last.IsZero() && now.Sub(last) < g.timing.staleAfter {
			continue
		}
		if stale == nil || last.Before(staleTime) {
			stale, staleTime = member, last
		}
	}
	if stale == nil {
		g.access.Unlock()
		return
	}
	stale.refreshing = true
	stale.refreshAt = now
	g.tasks.Add(1)
	attempt := groupAttempt{stale, g.attemptTimeout(stale)}
	g.access.Unlock()
	g.background(ctx, attempt, message.Copy(), epoch, false)
}

// background sends a copy of a query to a member and drops the reply: a probe of a member
// that is set aside, or a measurement of "fastest". The caller reserved it under the lock
// (probing or refreshing set, a task added). It ends with the timeout of an attempt or the
// close of the group.
func (g *GroupTransport) background(queryCtx context.Context, attempt groupAttempt, message *mDNS.Msg, epoch uint64, probe bool) {
	// the values of the query (its log ID) without its deadline: the reply has left already
	logCtx := context.WithoutCancel(queryCtx)
	go func() {
		defer g.tasks.Done()
		ctx, cancel := context.WithTimeout(logCtx, attempt.timeout)
		stop := context.AfterFunc(g.closing, cancel)
		startAt := time.Now()
		response, err := attempt.member.transport.Exchange(ctx, message)
		elapsed := time.Since(startAt)
		stop()
		cancel()
		response, err = groupResult(message, response, err)
		g.access.Lock()
		if probe {
			attempt.member.probing = false
		} else {
			attempt.member.refreshing = false
		}
		g.access.Unlock()
		if g.closing.Err() != nil {
			return
		}
		switch {
		case err == nil && isGroupAnswer(response):
			g.answered(logCtx, attempt.member, epoch, elapsed)
		case err != nil:
			g.failed(logCtx, attempt.member, epoch, startAt, err)
			g.logger.DebugContext(logCtx, "background query to server ", attempt.member.tag, " failed: ", err)
		}
	}()
}

// answered records an answer (NOERROR or NXDOMAIN) of a member that took elapsed.
func (g *GroupTransport) answered(ctx context.Context, member *groupMember, epoch uint64, elapsed time.Duration) {
	g.access.Lock()
	if epoch != g.epoch {
		g.access.Unlock()
		return
	}
	now := time.Now()
	elapsed = max(elapsed, time.Microsecond) // 0 means not measured
	if member.smoothed == 0 {
		member.smoothed = elapsed
	} else {
		member.smoothed += (elapsed - member.smoothed) / groupSmoothing
	}
	member.measuredAt, member.lastAnswer = now, now
	member.answers++
	g.answerSeq++
	member.failures = 0
	back := member.down
	member.down = false
	netBack := g.netInUse
	g.netInUse = false
	g.access.Unlock()
	if back {
		g.logger.WarnContext(stateContext(ctx), "server ", member.tag, " answers again")
	}
	if netBack {
		g.logger.WarnContext(stateContext(ctx), "server ", member.tag, " answers, provider DNS no longer used")
	}
}

// failed records a failure of a member for a query sent at startAt. Queries that were on
// their way when the last failure was counted are part of the same event and are not
// counted again (as fallbackServer.failure).
func (g *GroupTransport) failed(ctx context.Context, member *groupMember, epoch uint64, startAt time.Time, cause error) {
	g.access.Lock()
	if epoch != g.epoch {
		g.access.Unlock()
		return
	}
	member.failedTotal++
	if member.down || startAt.Before(member.countedAt) {
		g.access.Unlock()
		return
	}
	member.countedAt = time.Now()
	member.failures++
	if member.failures < fallbackDownAfter {
		g.access.Unlock()
		return
	}
	member.down = true
	member.probeEvery = g.timing.probeFirst
	member.probeAt = member.countedAt.Add(member.probeEvery)
	g.access.Unlock()
	// the logger formats only strings, numbers, errors and Stringers
	g.logger.WarnContext(stateContext(ctx), "server ", member.tag, " failed ", fallbackDownAfter, " times in a row (", cause, "), set aside until it answers again")
}

// netAnswered records an answer of the safety net to a query of the plan every member
// failed. A member that answered since the plan was made tells the state better: the net
// is not in use then (a probe brought a member back while the net was asked).
func (g *GroupTransport) netAnswered(ctx context.Context, plan groupPlan, cause error) {
	g.access.Lock()
	if plan.epoch != g.epoch {
		g.access.Unlock()
		return
	}
	g.netAnswer = time.Now()
	if g.answerSeq != plan.answers {
		g.access.Unlock()
		return
	}
	first := !g.netInUse
	g.netInUse = true
	net := g.net
	g.access.Unlock()
	if first {
		g.logger.WarnContext(stateContext(ctx), "every server failed (", cause, "), answering from provider DNS ", net.providers.names(), " until one answers again")
	}
}

func (g *GroupTransport) GroupState() adapter.DNSGroupState {
	g.access.Lock()
	defer g.access.Unlock()
	state := adapter.DNSGroupState{Strategy: g.strategy, SafetyNet: g.net != nil, SafetyNetAnswer: g.netAnswer}
	if g.members == nil {
		for _, tag := range g.tags {
			state.Members = append(state.Members, adapter.DNSGroupMemberState{Tag: tag})
		}
		return state
	}
	for _, member := range g.members {
		state.Members = append(state.Members, adapter.DNSGroupMemberState{
			Tag:          member.tag,
			Type:         member.transport.Type(),
			SetAside:     member.down,
			SmoothedTime: member.smoothed,
			LastAnswer:   member.lastAnswer,
			Answers:      member.answers,
			Failures:     member.failedTotal,
		})
	}
	return state
}

// groupResult turns an rcode returned as an error into the reply it stands for, as the
// client does (exchangeToTransport).
func groupResult(message *mDNS.Msg, response *mDNS.Msg, err error) (*mDNS.Msg, error) {
	var rcodeError RcodeError
	if err != nil && errors.As(err, &rcodeError) {
		return FixedResponseStatus(message, int(rcodeError)), nil
	}
	if err == nil && response == nil {
		return nil, E.New("empty response")
	}
	return response, err
}

func isGroupAnswer(response *mDNS.Msg) bool {
	return response.Rcode == mDNS.RcodeSuccess || response.Rcode == mDNS.RcodeNameError
}

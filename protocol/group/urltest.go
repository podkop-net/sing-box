package group

import (
	"context"
	"io"
	"maps"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/batch"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

func RegisterURLTest(registry *outbound.Registry) {
	outbound.Register[option.URLTestOutboundOptions](registry, C.TypeURLTest, NewURLTest)
}

var (
	_ adapter.OutboundGroup           = (*URLTest)(nil)
	_ adapter.InterfaceUpdateListener = (*URLTest)(nil)
	_ adapter.Referrer                = (*URLTest)(nil)
)

type URLTest struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	logger                       log.ContextLogger
	tags                         []string
	fallbackTags                 []string
	all                          []string
	link                         string
	downloadLink                 string
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	group                        *URLTestGroup
	checkAccess                  sync.Mutex
	interruptExternalConnections bool
}

func NewURLTest(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.URLTestOutboundOptions) (adapter.Outbound, error) {
	// a new slice: appending to the decoded options could write into their array
	all := slices.Concat(options.Outbounds, options.Fallbacks)
	outbound := &URLTest{
		Adapter:                      outbound.NewAdapter(C.TypeURLTest, tag, []string{N.NetworkTCP, N.NetworkUDP}, all),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		fallbackTags:                 options.Fallbacks,
		all:                          all,
		link:                         options.URL,
		interval:                     time.Duration(options.Interval),
		tolerance:                    options.Tolerance,
		idleTimeout:                  time.Duration(options.IdleTimeout),
		interruptExternalConnections: options.InterruptExistConnections,
	}
	// without outbounds the fallbacks are all there is (podkop-engine): a provider that took
	// every server away leaves what the rule falls back on
	if len(outbound.tags) == 0 && len(outbound.fallbackTags) == 0 {
		return nil, E.New("missing tags")
	}
	for i, tag := range outbound.tags {
		if slices.Contains(outbound.tags[:i], tag) {
			return nil, E.New("duplicate tag: ", tag)
		}
	}
	if len(outbound.fallbackTags) > 0 {
		listed := make(map[string]bool, len(all))
		for _, member := range outbound.tags {
			listed[member] = true
		}
		for _, member := range outbound.fallbackTags {
			if listed[member] {
				return nil, E.New("fallback ", member, " is already listed in outbounds or fallbacks")
			}
			listed[member] = true
		}
	}
	var err error
	outbound.downloadLink, err = groupDownloadLink(options.DownloadURL)
	if err != nil {
		return nil, err
	}
	if options.DownloadURL == nil && outbound.downloadLink != "" {
		err = checkDownloadLink("SING_BOX_URLTEST_DOWNLOAD_URL", outbound.downloadLink)
		if err != nil {
			logger.Warn("download test is off: ", err)
			outbound.downloadLink = ""
		}
	}
	return outbound, nil
}

func (s *URLTest) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateStart:
		outbounds := make([]adapter.Outbound, 0, len(s.tags))
		for i, tag := range s.tags {
			detour, loaded := s.outbound.Outbound(tag)
			if !loaded {
				return E.New("outbound ", i, " not found: ", tag)
			}
			outbounds = append(outbounds, detour)
		}
		fallbacks := make([]adapter.Outbound, 0, len(s.fallbackTags))
		for i, tag := range s.fallbackTags {
			detour, loaded := s.outbound.Outbound(tag)
			if !loaded {
				return E.New("fallback ", i, " not found: ", tag)
			}
			fallbacks = append(fallbacks, detour)
		}
		group, err := NewURLTestGroup(s.ctx, s.outbound, s.logger, outbounds, fallbacks, s.link, s.downloadLink, s.interval, s.tolerance, s.idleTimeout, s.interruptExternalConnections)
		if err != nil {
			return err
		}
		s.group = group
	case adapter.StartStateStarted:
		s.group.PostStart()
		scope.Add(s.group.Close)
	}
	return nil
}

func (s *URLTest) Now() string {
	if selected := s.group.selectedOutboundTCP.Load(); selected != nil {
		return selected.Tag()
	} else if selected := s.group.selectedOutboundUDP.Load(); selected != nil {
		return selected.Tag()
	}
	return ""
}

// All lists the outbounds, then the fallbacks.
func (s *URLTest) All() []string {
	return s.all
}

func (s *URLTest) Selected(network string) adapter.Outbound {
	var outbound adapter.Outbound
	if network == N.NetworkUDP {
		outbound = s.group.selectedOutboundUDP.Load()
	} else {
		outbound = s.group.selectedOutboundTCP.Load()
	}
	if outbound == nil {
		outbound, _ = s.group.Select(network)
	}
	return outbound
}

func (s *URLTest) AttachConnection(closer io.Closer) func() {
	s.group.Touch()
	return s.group.interruptGroup.Add(closer, true)
}

func (s *URLTest) References() []string {
	group := s.group
	if group == nil {
		return nil
	}
	var references []string
	selectedTCP, selectedUDP := group.selectedOutboundTCP.Load(), group.selectedOutboundUDP.Load()
	if selectedTCP != nil {
		references = append(references, selectedTCP.Tag())
	}
	if selectedUDP != nil && selectedUDP != selectedTCP {
		references = append(references, selectedUDP.Tag())
	}
	return references
}

func (s *URLTest) URLTest(ctx context.Context) (map[string]uint16, error) {
	return s.group.URLTest(ctx)
}

func (s *URLTest) CheckOutbounds() {
	s.group.CheckOutbounds(s.ctx, true)
}

// PerformUpdateCheck is the Clash API's: it does not wait for the selection, which may run a
// download test.
func (s *URLTest) PerformUpdateCheck() {
	s.group.requestUpdateCheck()
}

// NetworkReset is called at a reset of the network before the reset ends the dials in
// flight (podkop-engine).
func (s *URLTest) NetworkReset() {
	if s.group != nil {
		s.group.networkReset()
	}
}

func (s *URLTest) InterfaceUpdated(ctx context.Context) {
	group := s.group
	if group == nil {
		return
	}
	group.networkReset()
	// asked of the group, not of the manager: the group tells a report of no network
	// that the members have refuted (podkop-engine)
	if group.networkPaused() {
		return
	}
	go func() {
		s.checkAccess.Lock()
		defer s.checkAccess.Unlock()
		if ctx.Err() != nil {
			return
		}
		group.CheckOutbounds(ctx, true)
	}()
}

func (s *URLTest) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s.group.Touch()
	var outbound adapter.Outbound
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		outbound = s.group.selectedOutboundTCP.Load()
	case N.NetworkUDP:
		outbound = s.group.selectedOutboundUDP.Load()
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	if outbound == nil || s.group.selectionPending(outbound) {
		outbound, _ = s.group.Select(network)
	}
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	start := time.Now()
	conn, err := outbound.DialContext(ctx, network, destination)
	if err == nil {
		if N.NetworkName(network) == N.NetworkTCP {
			s.group.memberSucceeded(outbound)
		}
		var handshake *handshakeConn
		if N.NeedHandshakeForWrite(conn) {
			handshake = &handshakeConn{Conn: conn, failed: func(err error) {
				// a write that carries the connect is ended by a change of the network
				// as a dial is
				if !s.group.networkChangedSince(start) {
					s.group.memberFailed(ctx, outbound, N.NetworkName(network), err, time.Time{})
				}
			}}
			conn = handshake
		}
		if N.NetworkName(network) == N.NetworkTCP {
			if watched, isWatched := s.group.watchResponse(conn, outbound, destination).(*responseConn); isWatched {
				if handshake != nil {
					handshake.writing = watched.wrote // a write held back by the transport starts the clock
				}
				conn = watched
			}
		}
		return s.group.newUseConn(outbound, conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.group.memberFailed(ctx, outbound, N.NetworkName(network), err, start)
	return nil, memberError(outbound, err)
}

// memberError names the member a dial through the group failed on. The caller logs the
// error once, with the tag of the outbound it dialed (the group, or a selector above it):
// without the member in it nothing in the log says which server failed.
func memberError(member adapter.Outbound, err error) error {
	return E.Cause(err, "outbound/", member.Type(), "[", member.Tag(), "]")
}

func (s *URLTest) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s.group.Touch()
	outbound := s.group.selectedOutboundUDP.Load()
	if outbound == nil || s.group.selectionPending(outbound) {
		outbound, _ = s.group.Select(N.NetworkUDP)
	}
	if outbound == nil {
		return nil, E.New("missing supported outbound")
	}
	conn, err := outbound.ListenPacket(ctx, destination)
	if err == nil {
		return s.group.newUsePacketConn(outbound, conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.group.memberFailed(ctx, outbound, N.NetworkUDP, err, time.Time{})
	return nil, memberError(outbound, err)
}

type URLTestGroup struct {
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	pause                        pause.Manager
	pauseCallback                *list.Element[pause.Callback]
	logger                       log.Logger
	outbounds                    []adapter.Outbound
	fallbacks                    []adapter.Outbound
	members                      []adapter.Outbound // the outbounds, then the fallbacks: what a round tests
	link                         string
	interval                     time.Duration
	tolerance                    uint16
	idleTimeout                  time.Duration
	history                      *urltest.HistoryStorage
	checking                     atomic.Bool
	recheck                      atomic.Bool
	lastRound                    atomic.Int64  // when the last round began, since epoch
	roundDone                    atomic.Bool   // a round has tested the members (see selectAmong)
	blockRetry                   time.Duration // the delay of the round retryBlock armed last; under updateAccess
	blockRetryTimer              *time.Timer   // that round while it waits; under updateAccess
	selectedOutboundTCP          common.TypedValue[adapter.Outbound]
	selectedOutboundUDP          common.TypedValue[adapter.Outbound]
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool
	access                       sync.Mutex
	updateAccess                 sync.Mutex
	ticker                       *time.Ticker
	close                        chan struct{}
	started                      bool
	lastActive                   common.TypedValue[time.Time]
	updatePending                atomic.Bool
	confirmAccess                sync.Mutex
	confirms                     map[string]*memberConfirm
	unansweredConfirms           map[string]*memberConfirm
	epoch                        time.Time
	successes                    sync.Map // member tag → *atomic.Int64, its last successful TCP dial, since epoch
	localFailures                sync.Map // member tag → a failure of this host's own network waits to be judged
	// when the network last paused or woke, and when the pause in force was reported,
	// since epoch (networkChangedSince, networkPaused)
	networkEvent    atomic.Int64
	networkPauseAt  atomic.Int64
	networkCallback *list.Element[pause.Callback]
	downloadLink    string
	frozen          common.TypedValue[map[string]time.Time] // member tag → when it last failed the download test
	responses       sync.Map                                // member tag → *memberResponses
	responsesClosed atomic.Bool
	// cancel ends the rounds, the selection and the tests of the group at its close, and
	// closed tells it was closed: set under access, so that Touch starts no ticker after
	// (podkop-engine)
	cancel context.CancelFunc
	closed atomic.Bool
	// hotStart makes the first round test only the members without a result (TakeOver)
	hotStart bool
	// uses are the connections the group dialed that are open, by member (MembersInUse)
	useAccess sync.Mutex
	uses      map[adapter.Outbound]int
}

func NewURLTestGroup(ctx context.Context, outboundManager adapter.OutboundManager, logger log.Logger, outbounds []adapter.Outbound, fallbacks []adapter.Outbound, link string, downloadLink string, interval time.Duration, tolerance uint16, idleTimeout time.Duration, interruptExternalConnections bool) (*URLTestGroup, error) {
	if interval == 0 {
		interval = C.DefaultURLTestInterval
	}
	if tolerance == 0 {
		tolerance = 50
	}
	if idleTimeout == 0 {
		idleTimeout = C.DefaultURLTestIdleTimeout
	}
	if interval > idleTimeout {
		return nil, E.New("interval must be less or equal than idle_timeout")
	}
	history := service.PtrFromContext[urltest.HistoryStorage](ctx)
	if history == nil {
		return nil, E.New("missing URL test history storage")
	}
	ctx, cancel := context.WithCancel(ctx)
	group := &URLTestGroup{
		ctx:                          ctx,
		cancel:                       cancel,
		outbound:                     outboundManager,
		logger:                       logger,
		outbounds:                    outbounds,
		fallbacks:                    fallbacks,
		members:                      slices.Concat(outbounds, fallbacks),
		link:                         link,
		interval:                     interval,
		tolerance:                    tolerance,
		idleTimeout:                  idleTimeout,
		history:                      history,
		close:                        make(chan struct{}),
		pause:                        service.FromContext[pause.Manager](ctx),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: interruptExternalConnections,
		epoch:                        time.Now(),
		downloadLink:                 downloadLink,
		uses:                         make(map[adapter.Outbound]int),
	}
	group.watchPause(group.pause)
	return group, nil
}

func (g *URLTestGroup) PostStart() {
	g.access.Lock()
	defer g.access.Unlock()
	if g.closed.Load() {
		return
	}
	g.started = true
	g.lastActive.Store(time.Now())
	if g.hotStart {
		go g.checkUntested()
		return
	}
	go g.CheckOutbounds(g.ctx, false)
}

func (g *URLTestGroup) Touch() {
	if !g.started {
		return
	}
	g.access.Lock()
	defer g.access.Unlock()
	if g.closed.Load() {
		return
	}
	if g.ticker != nil {
		g.lastActive.Store(time.Now())
		g.probeUnseenNetwork()
		return
	}
	ticker := time.NewTicker(g.interval)
	g.ticker = ticker
	g.pauseCallback = pause.RegisterTicker(g.pause, ticker, g.interval, nil)
	g.keepTicking()
	go g.loopCheck(ticker, g.close)
}

func (g *URLTestGroup) Close() error {
	g.responsesClosed.Store(true)
	g.access.Lock()
	defer g.access.Unlock()
	if g.closed.Swap(true) {
		return nil
	}
	if g.cancel != nil {
		g.cancel()
	}
	if g.networkCallback != nil {
		g.pause.UnregisterCallback(g.networkCallback)
		g.networkCallback = nil
	}
	if g.ticker == nil {
		return nil
	}
	g.ticker.Stop()
	g.ticker = nil
	g.pause.UnregisterCallback(g.pauseCallback)
	g.pauseCallback = nil
	close(g.close)
	return nil
}

func (g *URLTestGroup) Select(network string) (adapter.Outbound, bool) {
	return g.selectAmong(network, nil)
}

// selectAmong is Select without the members that skip says to pass over. The fastest of the
// outbounds is chosen, by the tolerance; only when none of them is a candidate, the first
// fallback that is, in the order of the list.
func (g *URLTestGroup) selectAmong(network string, skip func(tag string, history *adapter.URLTestHistory) bool) (adapter.Outbound, bool) {
	var minDelay uint16
	var minOutbound adapter.Outbound
	var selected adapter.Outbound
	switch network {
	case N.NetworkTCP:
		selected = g.selectedOutboundTCP.Load()
	case N.NetworkUDP:
		selected = g.selectedOutboundUDP.Load()
	}
	// a fallback in use holds back no outbound: it is chosen only while none is a candidate
	if selected != nil && !g.isFallback(selected) {
		tag := RealTag(selected, network)
		if history := g.history.LoadURLTestHistory(tag); history != nil && (skip == nil || !skip(tag, history)) {
			minOutbound = selected
			minDelay = history.Delay
		}
	}
	for _, detour := range g.outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		tag := RealTag(detour, network)
		history := g.history.LoadURLTestHistory(tag)
		if history == nil || (skip != nil && skip(tag, history)) {
			continue
		}
		if minDelay == 0 || minDelay > history.Delay+g.tolerance {
			minDelay = history.Delay
			minOutbound = detour
		}
	}
	if minOutbound == nil {
		if !g.roundDone.Load() {
			// before a round has tested them the members have no results, which is no
			// reason to fall back (podkop-engine): at a start or after a swap a block
			// fallback would refuse every connection, a direct one send it past the proxy.
			// The first member, as without fallbacks; in a group of fallbacks alone the
			// first fallback, not a block further down.
			for _, detour := range g.members {
				if common.Contains(detour.Network(), network) {
					return detour, false
				}
			}
		}
		for _, detour := range g.fallbacks {
			if !common.Contains(detour.Network(), network) {
				continue
			}
			if detour.Type() == C.TypeBlock {
				// a block fallback answers by refusing (podkop-engine): it is what the
				// rule does when nothing before it answers, never tested
				return detour, true
			}
			tag := RealTag(detour, network)
			history := g.history.LoadURLTestHistory(tag)
			if history == nil || (skip != nil && skip(tag, history)) {
				continue
			}
			return detour, true
		}
		// the plain choice: the first outbound for the network, or, without one, fallback
		for _, detour := range g.members {
			if !common.Contains(detour.Network(), network) {
				continue
			}
			return detour, false
		}
		return nil, false
	}
	return minOutbound, true
}

func (g *URLTestGroup) isFallback(detour adapter.Outbound) bool {
	return len(g.fallbacks) > 0 && common.Contains(g.fallbacks, detour)
}

func (g *URLTestGroup) loopCheck(ticker *time.Ticker, closeChan <-chan struct{}) {
	if time.Since(g.lastActive.Load()) > g.interval {
		g.lastActive.Store(time.Now())
		g.CheckOutbounds(g.ctx, false)
	}
	for {
		select {
		case <-closeChan:
			return
		case <-ticker.C:
		}
		if time.Since(g.lastActive.Load()) > g.idleTimeout {
			g.access.Lock()
			if g.ticker == ticker {
				g.ticker.Stop()
				g.ticker = nil
				g.pause.UnregisterCallback(g.pauseCallback)
				g.pauseCallback = nil
			}
			g.access.Unlock()
			return
		}
		g.CheckOutbounds(g.ctx, false)
	}
}

// requestRecheck asks for one more forced round after the one in progress: that one
// began before whatever forced this one (a new default interface, mostly), and its
// results are of the old state.
func (g *URLTestGroup) requestRecheck() {
	g.recheck.Store(true)
	// that round may have ended, and looked at the flag, between the caller's look at it
	// and the statement above: then this call is the only one left to act on the flag
	if !g.checking.Load() && g.recheck.Swap(false) && g.ctx.Err() == nil && !g.networkPaused() {
		go g.CheckOutbounds(g.ctx, true)
	}
}

func (g *URLTestGroup) CheckOutbounds(ctx context.Context, force bool) {
	_, _ = g.urlTest(ctx, force)
}

// URLTest is the Clash API's round: it does not wait for the selection, which may run a
// download test, nor for those of the nested urltest groups.
func (g *URLTestGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	if g.closed.Load() {
		return nil, E.New("the group is closed")
	}
	// the round ends with the group too: a group that was replaced must not write results
	// for the tags another group tests now (podkop-engine)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(g.ctx, cancel)()
	result, err := g.urlTestRound(ctx, true, false)
	g.requestUpdateCheck()
	return result, err
}

func (g *URLTestGroup) urlTest(ctx context.Context, force bool) (map[string]uint16, error) {
	result, err := g.urlTestRound(ctx, force, true)
	g.performUpdateCheck()
	return result, err
}

// urlTestRound tests the members, one round at a time; the selection is not part of the round.
// With wait, a nested urltest group among the members selects within the round (see
// URLTestOutbounds).
func (g *URLTestGroup) urlTestRound(ctx context.Context, force bool, wait bool) (map[string]uint16, error) {
	return g.urlTestMembers(ctx, g.members, urlTestConcurrency, force, wait)
}

// urlTestMembers is urlTestRound of some of the members, so many at a time.
func (g *URLTestGroup) urlTestMembers(ctx context.Context, members []adapter.Outbound, concurrency int, force bool, wait bool) (map[string]uint16, error) {
	if g.closed.Load() {
		return make(map[string]uint16), nil
	}
	if g.checking.Swap(true) {
		if force {
			g.requestRecheck()
		}
		return make(map[string]uint16), nil
	}
	g.lastRound.Store(int64(time.Since(g.epoch)))
	defer func() {
		g.checking.Store(false)
		g.access.Lock()
		g.keepTicking()
		g.access.Unlock()
		if g.recheck.Swap(false) && g.ctx.Err() == nil && !g.networkPaused() {
			go g.CheckOutbounds(g.ctx, true)
		}
	}()
	result := urlTestOutbounds(ctx, g.outbound, g.history, g.logger, members, g.link, g.interval, force, wait, concurrency)
	if ctx.Err() == nil {
		// a round cut short (a delay test of the Clash API that timed out) tested only some
		g.roundDone.Store(true)
	}
	return result, nil
}

type urlTestResult struct {
	delay uint16
	err   error
}

type urlTestBatch struct {
	ctx      context.Context
	outbound adapter.OutboundManager
	history  *urltest.HistoryStorage
	logger   log.Logger
	batch    *batch.Batch[any]
	checked  map[string]bool
	groups   []adapter.OutboundGroup
	wait     bool
	access   sync.Mutex
	result   map[string]uint16
}

// URLTestOutbounds tests outbounds and, through them, the members of nested groups. A nested
// urltest group runs its own round and then selects. With wait, the call returns after
// that selection: a periodic round of the group above selects by the nested group's new
// choice. Without, the selection runs after the call returns: the Clash API answers its
// client in time, while the selection may run a download test of up to 15 s per candidate.
func URLTestOutbounds(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, force bool, wait bool) map[string]uint16 {
	return urlTestOutbounds(ctx, outboundManager, history, logger, outbounds, link, interval, force, wait, urlTestConcurrency)
}

// urlTestConcurrency is how many outbounds a round tests at a time.
const urlTestConcurrency = 10

func urlTestOutbounds(ctx context.Context, outboundManager adapter.OutboundManager, history *urltest.HistoryStorage, logger log.Logger, outbounds []adapter.Outbound, link string, interval time.Duration, force bool, wait bool, concurrency int) map[string]uint16 {
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](concurrency))
	testBatch := &urlTestBatch{
		ctx:      ctx,
		outbound: outboundManager,
		history:  history,
		logger:   logger,
		batch:    b,
		checked:  make(map[string]bool),
		wait:     wait,
		result:   make(map[string]uint16),
	}
	testBatch.test(outbounds, link, interval, force)
	b.Wait()
	for _, outboundGroup := range testBatch.groups {
		groupHistory := history.LoadURLTestHistory(RealTag(outboundGroup, N.NetworkTCP))
		if groupHistory != nil {
			testBatch.result[outboundGroup.Tag()] = groupHistory.Delay
		}
	}
	return testBatch.result
}

func (b *urlTestBatch) test(outbounds []adapter.Outbound, link string, interval time.Duration, force bool) {
	for _, detour := range outbounds {
		tag := detour.Tag()
		if b.checked[tag] || detour.Type() == C.TypeBlock {
			// a block fallback refuses every test: it answers by being chosen (selectAmong)
			continue
		}
		switch nested := detour.(type) {
		case *URLTest:
			b.checked[tag] = true
			b.groups = append(b.groups, nested)
			b.batch.Go(tag, func() (any, error) {
				var nestedResult map[string]uint16
				if b.wait {
					nestedResult, _ = nested.group.urlTest(b.ctx, force)
				} else {
					nestedResult, _ = nested.group.urlTestRound(b.ctx, force, false)
					nested.group.requestUpdateCheck()
				}
				b.access.Lock()
				maps.Copy(b.result, nestedResult)
				b.access.Unlock()
				return nil, nil
			})
		case adapter.OutboundGroup:
			b.checked[tag] = true
			b.groups = append(b.groups, nested)
			b.test(common.FilterNotNil(common.Map(nested.All(), func(it string) adapter.Outbound {
				member, _ := b.outbound.Outbound(it)
				return member
			})), link, interval, force)
		default:
			// A member that some group tested within this round is not tested again. The
			// group's own test from the previous round must not count: it finished at most
			// one test timeout after that round began, so it is at least interval minus that
			// timeout old. Comparing with the whole interval made every other round skip it.
			history := b.history.LoadURLTestHistory(tag)
			if !force && history != nil && time.Since(history.Time) < interval-C.TCPTimeout {
				continue
			}
			b.checked[tag] = true
			b.batch.Go(tag, func() (any, error) {
				var testResult urlTestResult
				testResult.delay, testResult.err = testOutbound(b.ctx, link, detour)
				if testResult.err != nil {
					if b.ctx.Err() != nil {
						return nil, nil
					}
					b.logger.Debug("outbound ", tag, " unavailable: ", testResult.err)
					b.history.DeleteURLTestHistory(tag)
				} else {
					if b.ctx.Err() != nil {
						// the round ended with its group (podkop-engine): the tag may be
						// another outbound's by now
						return nil, nil
					}
					b.logger.Debug("outbound ", tag, " available: ", testResult.delay, "ms")
					b.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{
						Time:  time.Now(),
						Delay: testResult.delay,
					})
					b.access.Lock()
					b.result[tag] = testResult.delay
					b.access.Unlock()
				}
				return nil, nil
			})
		}
	}
}

func (g *URLTestGroup) performUpdateCheck() {
	g.updateAccess.Lock()
	defer g.updateAccess.Unlock()
	g.updateSelection()
}

// updateSelection is performUpdateCheck under its lock. A group that was closed selects no
// more (podkop-engine): its download test is canceled with it, and what it would choose then
// was not tested.
func (g *URLTestGroup) updateSelection() {
	if g.closed.Load() {
		return
	}
	if g.downloadLink != "" {
		// new dials already pass over a member without a test result while the selection
		// waits (selectionPending), which the download test may make long
		g.closeUnanswered()
	}
	var (
		updated  bool
		selected bool
	)
	// the selection is read by every dial, which may run while it changes: stored atomically
	outbound, exists := g.selectTested()
	if g.closed.Load() {
		return
	}
	if outbound != nil {
		if current := g.selectedOutboundTCP.Load(); current == nil || (exists && outbound != current) {
			if current != nil {
				updated = true
				if g.isFallback(outbound) {
					g.logger.Warn("switched from outbound ", current.Tag(), " to fallback ", outbound.Tag())
				} else {
					g.logger.Warn("switched from outbound ", current.Tag(), " to ", outbound.Tag())
				}
			}
			g.selectedOutboundTCP.Store(outbound)
			selected = true
		}
	}
	if outbound, exists := g.selectUDP(); outbound != nil {
		if current := g.selectedOutboundUDP.Load(); current == nil || (exists && outbound != current) {
			if current != nil {
				updated = true
			}
			g.selectedOutboundUDP.Store(outbound)
			selected = true
		}
	}
	if g.closed.Load() {
		return
	}
	if updated {
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
	}
	if selected {
		g.history.NotifyUpdated()
	}
	g.retryBlock()
	g.closeUnanswered()
}

// blockRetryFirst is how soon a round follows a selection that left a block fallback chosen
// (podkop-engine), twice as long each time it still does, at most an interval. Block is
// never tested and the dials it refuses reach no member, so without these rounds the
// servers would come back at the next periodic round only, minutes after the network that
// failed them (an outage of the provider, a start before the WAN is up).
var blockRetryFirst = 30 * time.Second

// retryBlock arms that round while the TCP choice is a block fallback, and forgets the delay
// once it is not. Called under updateAccess.
func (g *URLTestGroup) retryBlock() {
	current := g.selectedOutboundTCP.Load()
	if current == nil || current.Type() != C.TypeBlock || !g.isFallback(current) {
		g.blockRetry = 0
		if g.blockRetryTimer != nil {
			g.blockRetryTimer.Stop()
			g.blockRetryTimer = nil
		}
		return
	}
	if g.blockRetryTimer != nil {
		return
	}
	if g.blockRetry == 0 {
		g.blockRetry = blockRetryFirst
	} else {
		g.blockRetry = min(2*g.blockRetry, g.interval)
	}
	var timer *time.Timer
	timer = time.AfterFunc(g.blockRetry, func() {
		g.updateAccess.Lock()
		if g.blockRetryTimer == timer {
			// a selection may have disarmed this timer and armed another while this waited
			g.blockRetryTimer = nil
		}
		// an idle group is tested again when a dial comes (Touch), a paused network when it
		// is back (watchPause); the retries then start over from the first delay
		resting := g.closed.Load() || g.ctx.Err() != nil || g.networkPaused() || time.Since(g.lastActive.Load()) > g.idleTimeout
		if resting {
			g.blockRetry = 0
		}
		g.updateAccess.Unlock()
		if !resting {
			// not forced: the members without a result, the ones block stands for, are
			// tested anyway, and a round in progress selects at its end
			g.CheckOutbounds(g.ctx, false)
		}
	})
	g.blockRetryTimer = timer
}

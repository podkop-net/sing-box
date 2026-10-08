package group

import (
	"context"
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
	"github.com/sagernet/sing-tun"
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

var _ adapter.OutboundGroup = (*URLTest)(nil)

type URLTest struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	connection                   adapter.ConnectionManager
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
	interruptExternalConnections bool
}

func NewURLTest(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.URLTestOutboundOptions) (adapter.Outbound, error) {
	// a new slice: appending to the decoded options could write into their array
	all := slices.Concat(options.Outbounds, options.Fallbacks)
	outbound := &URLTest{
		Adapter:                      outbound.NewAdapter(C.TypeURLTest, tag, []string{N.NetworkTCP, N.NetworkUDP}, all),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
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
	if len(outbound.tags) == 0 {
		return nil, E.New("missing tags")
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

func (s *URLTest) Start() error {
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
	return nil
}

func (s *URLTest) PostStart() error {
	s.group.PostStart()
	return nil
}

func (s *URLTest) Close() error {
	return common.Close(
		common.PtrOrNil(s.group),
	)
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

func (s *URLTest) URLTest(ctx context.Context) (map[string]uint16, error) {
	return s.group.URLTest(ctx)
}

func (s *URLTest) CheckOutbounds() {
	s.group.CheckOutbounds(true)
}

// PerformUpdateCheck is the Clash API's: it does not wait for the selection, which may run a
// download test.
func (s *URLTest) PerformUpdateCheck() {
	s.group.requestUpdateCheck()
}

// InterfaceUpdated re-checks the group when the default interface changes
// (e.g. WAN came up after boot), instead of waiting for the next interval.
func (s *URLTest) InterfaceUpdated() {
	if s.group != nil && !s.group.networkPaused() {
		go s.group.CheckOutbounds(true)
	}
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
			handshake = &handshakeConn{Conn: conn, failed: func(err error) { s.group.memberFailed(ctx, outbound, N.NetworkName(network), err, time.Time{}) }}
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
		return s.group.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, err)
	s.group.memberFailed(ctx, outbound, N.NetworkName(network), err, start)
	return nil, err
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
		return s.group.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
	}
	s.logger.ErrorContext(ctx, err)
	s.group.memberFailed(ctx, outbound, N.NetworkUDP, err, time.Time{})
	return nil, err
}

func (s *URLTest) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewConnection(ctx, s, conn, metadata, onClose)
}

func (s *URLTest) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	s.connection.NewPacketConnection(ctx, s, conn, metadata, onClose)
}

func (s *URLTest) NewDirectRouteConnection(metadata adapter.InboundContext, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	s.group.Touch()
	selected := s.group.selectedOutboundTCP.Load()
	if selected == nil {
		selected, _ = s.group.Select(N.NetworkTCP)
	}
	if selected == nil {
		return nil, E.New("missing supported outbound")
	}
	if !common.Contains(selected.Network(), metadata.Network) {
		return nil, E.New(metadata.Network, " is not supported by outbound: ", selected.Tag())
	}
	return selected.(adapter.DirectRouteOutbound).NewDirectRouteConnection(metadata, routeContext, timeout)
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
	history                      adapter.URLTestHistoryStorage
	checking                     atomic.Bool
	recheck                      atomic.Bool
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
	downloadLink                 string
	frozen                       common.TypedValue[map[string]time.Time] // member tag → when it last failed the download test
	responses                    sync.Map                                // member tag → *memberResponses
	responsesClosed              atomic.Bool
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
	var history adapter.URLTestHistoryStorage
	if historyFromCtx := service.PtrFromContext[urltest.HistoryStorage](ctx); historyFromCtx != nil {
		history = historyFromCtx
	} else if clashServer := service.FromContext[adapter.ClashServer](ctx); clashServer != nil {
		history = clashServer.HistoryStorage()
	} else {
		history = urltest.NewHistoryStorage()
	}
	return &URLTestGroup{
		ctx:                          ctx,
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
	}, nil
}

func (g *URLTestGroup) PostStart() {
	g.access.Lock()
	defer g.access.Unlock()
	g.started = true
	g.lastActive.Store(time.Now())
	go g.CheckOutbounds(false)
}

func (g *URLTestGroup) Touch() {
	if !g.started {
		return
	}
	g.access.Lock()
	defer g.access.Unlock()
	if g.ticker != nil {
		g.lastActive.Store(time.Now())
		return
	}
	ticker := time.NewTicker(g.interval)
	g.ticker = ticker
	g.pauseCallback = pause.RegisterTicker(g.pause, ticker, g.interval, nil)
	go g.loopCheck(ticker, g.close)
}

func (g *URLTestGroup) Close() error {
	g.responsesClosed.Store(true)
	g.access.Lock()
	defer g.access.Unlock()
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
		tag := RealTag(selected)
		if history := g.history.LoadURLTestHistory(tag); history != nil && (skip == nil || !skip(tag, history)) {
			minOutbound = selected
			minDelay = history.Delay
		}
	}
	for _, detour := range g.outbounds {
		if !common.Contains(detour.Network(), network) {
			continue
		}
		tag := RealTag(detour)
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
		for _, detour := range g.fallbacks {
			if !common.Contains(detour.Network(), network) {
				continue
			}
			tag := RealTag(detour)
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
		g.CheckOutbounds(false)
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
		g.CheckOutbounds(false)
	}
}

func (g *URLTestGroup) CheckOutbounds(force bool) {
	_, _ = g.urlTest(g.ctx, force)
}

// URLTest is the Clash API's round: it does not wait for the selection, which may run a
// download test.
func (g *URLTestGroup) URLTest(ctx context.Context) (map[string]uint16, error) {
	result, err := g.urlTestRound(ctx, false)
	g.requestUpdateCheck()
	return result, err
}

func (g *URLTestGroup) urlTest(ctx context.Context, force bool) (map[string]uint16, error) {
	result, err := g.urlTestRound(ctx, force)
	g.performUpdateCheck()
	return result, err
}

type urlTestResult struct {
	delay uint16
	err   error
}

// urlTestRound tests the members, one round at a time; the selection is not part of the round.
func (g *URLTestGroup) urlTestRound(ctx context.Context, force bool) (map[string]uint16, error) {
	result := make(map[string]uint16)
	if g.checking.Swap(true) {
		if force {
			// the round in progress began before whatever forced this one (a new default
			// interface, mostly): its results are of the old state, so another follows it
			g.recheck.Store(true)
		}
		return result, nil
	}
	defer func() {
		g.checking.Store(false)
		if g.recheck.Swap(false) && g.ctx.Err() == nil && !g.networkPaused() {
			go g.CheckOutbounds(true)
		}
	}()
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[any](10))
	checked := make(map[string]bool)
	var resultAccess sync.Mutex
	for _, detour := range g.members {
		tag := detour.Tag()
		realTag := RealTag(detour)
		if checked[realTag] {
			continue
		}
		// A member that some group tested within this round is not tested again. The
		// group's own test from the previous round must not count: it finished at most one
		// test timeout after that round began, so it is at least interval minus that timeout
		// old. Comparing with the whole interval made every other round skip it.
		history := g.history.LoadURLTestHistory(realTag)
		if !force && history != nil && time.Since(history.Time) < g.interval-C.TCPTimeout {
			continue
		}
		checked[realTag] = true
		p, loaded := g.outbound.Outbound(realTag)
		if !loaded {
			continue
		}
		b.Go(realTag, func() (any, error) {
			var testResult urlTestResult
			testResult.delay, testResult.err = testOutbound(g.ctx, g.link, p)
			if testResult.err != nil {
				g.logger.Debug("outbound ", tag, " unavailable: ", testResult.err)
				g.history.DeleteURLTestHistory(realTag)
			} else {
				g.logger.Debug("outbound ", tag, " available: ", testResult.delay, "ms")
				g.history.StoreURLTestHistory(realTag, &adapter.URLTestHistory{
					Time:  time.Now(),
					Delay: testResult.delay,
				})
				resultAccess.Lock()
				result[tag] = testResult.delay
				resultAccess.Unlock()
			}
			return nil, nil
		})
	}
	b.Wait()
	return result, nil
}

func (g *URLTestGroup) performUpdateCheck() {
	g.updateAccess.Lock()
	defer g.updateAccess.Unlock()
	g.updateSelection()
}

// updateSelection is performUpdateCheck under its lock.
func (g *URLTestGroup) updateSelection() {
	if g.downloadLink != "" {
		// new dials already pass over a member without a test result while the selection
		// waits (selectionPending), which the download test may make long
		g.closeUnanswered()
	}
	var updated bool
	// the selection is read by every dial, which may run while it changes: stored atomically
	if outbound, exists := g.selectTested(); outbound != nil {
		if selected := g.selectedOutboundTCP.Load(); selected == nil || (exists && outbound != selected) {
			if selected != nil {
				updated = true
				if g.isFallback(outbound) {
					g.logger.Warn("switched from outbound ", selected.Tag(), " to fallback ", outbound.Tag())
				} else {
					g.logger.Warn("switched from outbound ", selected.Tag(), " to ", outbound.Tag())
				}
			}
			g.selectedOutboundTCP.Store(outbound)
		}
	}
	if outbound, exists := g.selectUDP(); outbound != nil {
		if selected := g.selectedOutboundUDP.Load(); selected == nil || (exists && outbound != selected) {
			if selected != nil {
				updated = true
			}
			g.selectedOutboundUDP.Store(outbound)
		}
	}
	if updated {
		g.interruptGroup.Interrupt(g.interruptExternalConnections)
	}
	g.closeUnanswered()
}

package box

import (
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// Outbounds changed while the box runs (podkop-engine).
//
// The router, the Clash API and the reference manager find an outbound by its tag for every
// connection. UpdateOutbounds builds the new outbounds, each in a scope of its own, starts
// them and puts them in the manager under their tags; a connection routed after that goes
// through them, and one routed before keeps the objects of its chain. The outbounds that
// were replaced or taken out are kept until no connection goes through them (drainOutbounds).

var (
	// drainMin is how long an outbound that was replaced or taken out is kept at least: a dial
	// no list shows may still use it (a download through a server, a test).
	drainMin = 2 * time.Minute
	// drainMax is how long it is kept at most: a connection older than that through it is cut
	// when its transport is shared (gRPC, HTTP/2, XHTTP, QUIC, multiplex).
	drainMax = 24 * time.Hour
	// drainEvery is how often the connections are looked at.
	drainEvery = 30 * time.Second
)

// ErrTooManyKept is what UpdateOutbounds returns when more outbounds of the changes before
// than its limit still carry connections: a new box lets them all go.
var ErrTooManyKept = E.New("too many outbounds of the changes before still carry connections")

// OutboundUpdate tells what UpdateOutbounds changed.
type OutboundUpdate struct {
	Added    int
	Replaced int
	Removed  int
	// Kept is how many of the outbounds replaced or taken out, by this change and those
	// before, are not closed yet.
	Kept int
}

// hotOutbounds is what UpdateOutbounds keeps between its calls. access is held for a whole
// update.
type hotOutbounds struct {
	access sync.Mutex
	// scopes are those of the outbounds UpdateOutbounds started: in the manager, or kept
	scopes map[adapter.Outbound]*adapter.Scope
	kept   []*keptOutbound
	// draining tells that drainOutbounds runs, closing that a cleanup of the box closes the
	// outbounds of scopes, closed that it did
	draining bool
	closing  bool
	closed   bool
}

type keptOutbound struct {
	outbound adapter.Outbound
	since    time.Time
	// needs are what it goes through while a connection goes through it: the outbound it
	// dials through, the member a selector chose. A urltest group tells its own
	// (memberUser).
	needs []adapter.Outbound
}

// What the groups do in an update (protocol/group).
type (
	// outboundSuccessor takes over what the outbound it replaces knew; called after the
	// start stage, before it is started
	outboundSuccessor interface {
		TakeOver(previous adapter.Outbound)
	}
	// retiringOutbound stops what it does on its own once it is replaced or taken out
	retiringOutbound interface {
		Retire()
	}
	// memberReleaser lets go of its members, drainMin after it was replaced or taken out:
	// a connection holds the outbounds of its chain as long as the Clash API lists it, and
	// a group must not hold all its members with it
	memberReleaser interface {
		ReleaseMembers()
	}
	// memberUser tells the members the connections it dialed go through now
	memberUser interface {
		MembersInUse() []adapter.Outbound
	}
)

// UpdateOutbounds changes the outbounds of the started box while it runs (podkop-engine).
// Each of outbounds is built, started after those of its dependencies among them, and takes
// the place of the outbound of its tag, or is added; the outbounds of the tags in remove are
// taken out. A urltest group that is replaced stops testing and choosing, and the one that
// replaces it takes over its choice and tests only the members without a test result. An
// outbound replaced or taken out is closed once no connection goes through it, at least
// drainMin and at most drainMax after.
//
// An outbound that stays must not depend on one that is replaced or taken out: it keeps the
// one it found at its start. Such an update is refused, and so is one while more than limit
// outbounds that are not groups are kept (0: no limit, ErrTooManyKept). The caller makes sure
// that no DNS server or HTTP client dials through an outbound that changes, for the same
// reason. Nothing is changed by an update that is refused or fails: the outbounds of before
// are put back and the new ones closed.
func (s *Box) UpdateOutbounds(outbounds []option.Outbound, remove []string, limit int) (OutboundUpdate, error) {
	hot := &s.hot
	hot.access.Lock()
	defer hot.access.Unlock()
	var update OutboundUpdate
	ctx := s.scope.Context()
	if !hot.closing && !hot.closed {
		hot.closing = true
		s.scope.Add(s.closeHotOutbounds)
	}
	// after the cleanup is in: a box that began to close since has its context canceled
	if hot.closed || ctx.Err() != nil {
		return update, E.New("sing-box is closed")
	}
	if limit > 0 && hot.keptServers() > limit {
		return update, ErrTooManyKept
	}
	current := make(map[string]adapter.Outbound)
	for _, outbound := range s.outbound.Outbounds() {
		current[outbound.Tag()] = outbound
	}
	given := make(map[string]bool, len(outbounds))
	changed := make(map[string]bool, len(outbounds)+len(remove))
	for i, options := range outbounds {
		switch {
		case options.Tag == "":
			return update, E.New("outbound[", i, "]: missing tag")
		case given[options.Tag]:
			return update, E.New("duplicate outbound tag: ", options.Tag)
		}
		given[options.Tag] = true
		if _, exists := current[options.Tag]; exists {
			changed[options.Tag] = true
		} else if _, isEndpoint := s.endpoint.Get(options.Tag); isEndpoint {
			return update, E.New("outbound tag is that of an endpoint: ", options.Tag)
		}
	}
	for _, tag := range remove {
		if given[tag] || changed[tag] {
			return update, E.New("outbound ", tag, " is given and removed")
		}
		if _, exists := current[tag]; !exists {
			return update, E.New("outbound to remove not found: ", tag)
		}
		changed[tag] = true
	}
	stays := make([]adapter.Outbound, 0, len(current))
	for _, outbound := range s.outbound.Outbounds() {
		if !changed[outbound.Tag()] && !given[outbound.Tag()] {
			stays = append(stays, outbound)
		}
	}
	for _, endpoint := range s.endpoint.Endpoints() {
		stays = append(stays, endpoint)
	}
	for _, outbound := range stays {
		for _, dependency := range outbound.Dependencies() {
			if changed[dependency] {
				return update, E.New("outbound ", outbound.Tag(), " goes through ", dependency, ", which changes: it has to be given too")
			}
		}
	}
	// what the outbounds that go need while they are kept: the objects of now
	needs := make(map[adapter.Outbound][]adapter.Outbound)
	for tag := range changed {
		outbound := current[tag]
		needs[outbound] = outboundNeeds(outbound, current)
	}

	entries := make([]*hotEntry, 0, len(outbounds))
	closeEntries := func() {
		for _, entry := range slices.Backward(entries) {
			// a group that was not started registered no close of its own
			if retiring, isRetiring := entry.outbound.(retiringOutbound); isRetiring {
				retiring.Retire()
			}
			err := entry.scope.Close()
			if err != nil {
				s.logger.Warn("close outbound/", entry.outbound.Type(), "[", entry.outbound.Tag(), "]: ", err)
			}
		}
	}
	for _, options := range outbounds {
		scope := adapter.NewScope(ctx, s.logFactory.Logger())
		outboundCtx := adapter.WithContext(scope.Context(), &adapter.InboundContext{Outbound: options.Tag})
		outbound, err := s.outbound.NewOutbound(outboundCtx, s.router, s.logFactory.NewLogger(F.ToString("outbound/", options.Type, "[", options.Tag, "]")),
			options.Tag, options.Type, options.Options)
		if err != nil {
			scope.Close()
			closeEntries()
			return update, E.Cause(err, "initialize outbound[", options.Tag, "]")
		}
		entries = append(entries, &hotEntry{outbound: outbound, scope: scope, previous: current[options.Tag]})
	}
	// a new outbound must not go through one taken out: it would find it at its start, still
	// in the manager, and keep it
	removing := make(map[string]bool, len(remove))
	for _, tag := range remove {
		removing[tag] = true
	}
	for _, entry := range entries {
		for _, dependency := range entry.outbound.Dependencies() {
			if removing[dependency] {
				closeEntries()
				return update, E.New("outbound ", entry.outbound.Tag(), " goes through ", dependency, ", which is removed")
			}
		}
	}
	layers, err := hotLayers(entries)
	if err != nil {
		closeEntries()
		return update, err
	}

	var (
		previous []adapter.Outbound
		added    []string
		removed  []adapter.Outbound
	)
	rollback := func(cause error) error {
		_, swapErr := s.outbound.SwapOutbounds(append(previous, removed...), added)
		if swapErr != nil {
			s.logger.Error("put back the outbounds of before: ", swapErr)
		}
		closeEntries()
		return cause
	}
	for _, layer := range layers {
		put := make([]adapter.Outbound, len(layer))
		for i, entry := range layer {
			for _, stage := range []adapter.StartStage{adapter.StartStateInitialize, adapter.StartStateStart} {
				err = entry.start(stage)
				if err != nil {
					return update, rollback(err)
				}
			}
			put[i] = entry.outbound
		}
		replaced, err := s.outbound.SwapOutbounds(put, nil)
		if err != nil {
			return update, rollback(err)
		}
		previous = append(previous, replaced...)
		for _, entry := range layer {
			if entry.previous == nil {
				added = append(added, entry.outbound.Tag())
			}
		}
	}
	if len(remove) > 0 {
		removed, err = s.outbound.SwapOutbounds(nil, remove)
		if err != nil {
			return update, rollback(err)
		}
	}
	// What the groups found through an outbound that is replaced or taken out is not the result of
	// the one that takes its tag: forgotten before the new groups look at the results, so they test
	// it. A round of a group being replaced may have stored one up to now.
	if history := service.PtrFromContext[urltest.HistoryStorage](ctx); history != nil {
		for _, outbound := range append(slices.Clone(previous), removed...) {
			if _, isGroup := outbound.(adapter.OutboundGroup); !isGroup {
				history.DeleteURLTestHistory(outbound.Tag())
			}
		}
	}
	for _, entry := range entries {
		if successor, isSuccessor := entry.outbound.(outboundSuccessor); isSuccessor && entry.previous != nil {
			successor.TakeOver(entry.previous)
		}
	}
	for _, layer := range layers {
		for _, entry := range layer {
			for _, stage := range []adapter.StartStage{adapter.StartStatePostStart, adapter.StartStateStarted} {
				err = entry.start(stage)
				if err != nil {
					return update, rollback(err)
				}
			}
		}
	}

	if hot.scopes == nil {
		hot.scopes = make(map[adapter.Outbound]*adapter.Scope)
	}
	for _, entry := range entries {
		hot.scopes[entry.outbound] = entry.scope
	}
	now := time.Now()
	retired := append(previous, removed...)
	for _, outbound := range retired {
		if retiring, isRetiring := outbound.(retiringOutbound); isRetiring {
			retiring.Retire()
		}
		hot.kept = append(hot.kept, &keptOutbound{outbound: outbound, since: now, needs: needs[outbound]})
	}
	time.AfterFunc(drainMin, func() {
		for _, outbound := range retired {
			if releaser, isReleaser := outbound.(memberReleaser); isReleaser {
				releaser.ReleaseMembers()
			}
		}
	})
	if !hot.draining && len(hot.kept) > 0 {
		hot.draining = true
		go s.drainOutbounds(drainEvery)
	}
	// the reference manager looks at the outbounds again: which keep their idle connections
	if history := service.PtrFromContext[urltest.HistoryStorage](ctx); history != nil {
		history.NotifyUpdated()
	}
	update.Added = len(added)
	update.Replaced = len(previous)
	update.Removed = len(removed)
	update.Kept = len(hot.kept)
	return update, nil
}

type hotEntry struct {
	outbound adapter.Outbound
	scope    *adapter.Scope
	// previous is the outbound of the tag before, nil for a new tag
	previous adapter.Outbound
}

func (e *hotEntry) start(stage adapter.StartStage) error {
	lifecycle, isLifecycle := e.outbound.(adapter.Lifecycle)
	if !isLifecycle {
		return nil
	}
	return e.scope.Start("outbound/"+e.outbound.Type()+"["+e.outbound.Tag()+"]", lifecycle, stage)
}

// hotLayers orders the entries by their dependencies among them: an entry is in a layer
// after those of what it depends on.
func hotLayers(entries []*hotEntry) ([][]*hotEntry, error) {
	byTag := make(map[string]*hotEntry, len(entries))
	for _, entry := range entries {
		byTag[entry.outbound.Tag()] = entry
	}
	layerOf := make(map[*hotEntry]int, len(entries))
	var place func(entry *hotEntry, path []string) (int, error)
	place = func(entry *hotEntry, path []string) (int, error) {
		if layer, placed := layerOf[entry]; placed {
			if layer < 0 {
				return 0, E.New("circular outbound dependency: ", path)
			}
			return layer, nil
		}
		layerOf[entry] = -1
		layer := 0
		for _, dependency := range entry.outbound.Dependencies() {
			needed, isEntry := byTag[dependency]
			if !isEntry {
				continue
			}
			neededLayer, err := place(needed, append(path, dependency))
			if err != nil {
				return 0, err
			}
			layer = max(layer, neededLayer+1)
		}
		layerOf[entry] = layer
		return layer, nil
	}
	var layers [][]*hotEntry
	for _, entry := range entries {
		layer, err := place(entry, []string{entry.outbound.Tag()})
		if err != nil {
			return nil, err
		}
		for len(layers) <= layer {
			layers = append(layers, nil)
		}
		layers[layer] = append(layers[layer], entry)
	}
	return layers, nil
}

// outboundNeeds is what an outbound that goes goes through while it is kept, of the
// outbounds of now (keptOutbound.needs).
func outboundNeeds(outbound adapter.Outbound, current map[string]adapter.Outbound) []adapter.Outbound {
	if _, isUser := outbound.(memberUser); isUser {
		return nil
	}
	var needs []adapter.Outbound
	if group, isGroup := outbound.(adapter.OutboundGroup); isGroup {
		for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
			if selected := group.Selected(network); selected != nil && !slices.Contains(needs, selected) {
				needs = append(needs, selected)
			}
		}
		return needs
	}
	for _, dependency := range outbound.Dependencies() {
		if needed, exists := current[dependency]; exists {
			needs = append(needs, needed)
		}
	}
	return needs
}

// keptServers counts the kept outbounds that are not groups: those that hold the memory.
func (h *hotOutbounds) keptServers() int {
	var count int
	for _, kept := range h.kept {
		if _, isGroup := kept.outbound.(adapter.OutboundGroup); !isGroup {
			count++
		}
	}
	return count
}

// drainOutbounds closes the kept outbounds that no connection goes through any more, every so
// often, until none is kept or the box closes.
func (s *Box) drainOutbounds(every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	done := s.scope.Context().Done()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
		}
		if !s.drainOnce(time.Now()) {
			return
		}
	}
}

// drainOnce closes the kept outbounds that may be closed at now, and tells whether any is
// still kept.
func (s *Box) drainOnce(now time.Time) bool {
	hot := &s.hot
	hot.access.Lock()
	if hot.closed {
		hot.draining = false
		hot.access.Unlock()
		return false
	}
	held, known := s.heldOutbounds(hot.kept)
	var (
		closing []*keptOutbound
		scopes  []*adapter.Scope
		cut     int
		kept    = make([]*keptOutbound, 0, len(hot.kept))
	)
	for _, outbound := range hot.kept {
		age := now.Sub(outbound.since)
		if age < drainMin || age < drainMax && (!known || held[outbound.outbound]) {
			kept = append(kept, outbound)
			continue
		}
		if held[outbound.outbound] {
			cut++
		}
		closing = append(closing, outbound)
	}
	// the groups first: what went through a member is closed before it
	slices.SortStableFunc(closing, func(a, b *keptOutbound) int {
		_, aGroup := a.outbound.(adapter.OutboundGroup)
		_, bGroup := b.outbound.(adapter.OutboundGroup)
		switch {
		case aGroup && !bGroup:
			return -1
		case bGroup && !aGroup:
			return 1
		}
		return 0
	})
	for _, outbound := range closing {
		scopes = append(scopes, hot.scopes[outbound.outbound])
		delete(hot.scopes, outbound.outbound)
	}
	hot.kept = kept
	hot.draining = len(kept) > 0
	hot.access.Unlock()
	for i, outbound := range closing {
		var err error
		if scopes[i] != nil {
			err = scopes[i].Close()
		} else if lifecycle, isLifecycle := outbound.outbound.(adapter.Lifecycle); isLifecycle {
			_, err = s.scope.CloseComponent(lifecycle)
		}
		if err != nil {
			s.logger.Warn("close outbound/", outbound.outbound.Type(), "[", outbound.outbound.Tag(), "]: ", err)
		}
	}
	if cut > 0 {
		s.logger.Info("closed ", cut, " replaced outbounds that still carried connections, ", drainMax, " after the change")
	}
	if len(closing) > 0 {
		s.logger.Debug("closed ", len(closing), " replaced outbounds, ", len(kept), " still kept")
	}
	return len(kept) > 0
}

// heldOutbounds finds the kept outbounds a connection goes through: those in the chain of an
// open connection, a kept urltest group that dialed a connection that is open and the member
// it went through, and what these go through (keptOutbound.needs). It tells false when no connection is
// tracked (no Clash API): every kept outbound is held then.
func (s *Box) heldOutbounds(kept []*keptOutbound) (map[adapter.Outbound]bool, bool) {
	connections := service.PtrFromContext[trafficcontrol.Manager](s.scope.Context())
	if connections == nil {
		return nil, false
	}
	index := make(map[adapter.Outbound]*keptOutbound, len(kept))
	for _, outbound := range kept {
		index[outbound.outbound] = outbound
	}
	held := make(map[adapter.Outbound]bool)
	var queue []*keptOutbound
	hold := func(outbound adapter.Outbound) {
		if keptOutbound, isKept := index[outbound]; isKept && !held[outbound] {
			held[outbound] = true
			queue = append(queue, keptOutbound)
		}
	}
	for _, connection := range connections.Connections() {
		for _, outbound := range connection.Metadata.OutboundChain {
			hold(outbound)
		}
	}
	for _, outbound := range kept {
		if user, isUser := outbound.outbound.(memberUser); isUser {
			// the group too: it is asked again at the next look
			if members := user.MembersInUse(); len(members) > 0 {
				hold(outbound.outbound)
				for _, member := range members {
					hold(member)
				}
			}
		}
	}
	for len(queue) > 0 {
		outbound := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		for _, needed := range outbound.needs {
			hold(needed)
		}
	}
	return held, true
}

// closeHotOutbounds closes the outbounds UpdateOutbounds started, with the box: the scope of
// the box does not hold them.
func (s *Box) closeHotOutbounds() error {
	hot := &s.hot
	hot.access.Lock()
	hot.closed = true
	scopes := hot.scopes
	hot.scopes = nil
	hot.kept = nil
	hot.access.Unlock()
	var errors []error
	for _, scope := range scopes {
		errors = append(errors, scope.Close())
	}
	return E.Errors(errors...)
}

package urltestgroup

import (
	"context"
	"errors"
	"github.com/sagernet/sing-box/protocol/group"
	"slices"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

// The modes of a group (podkop-engine).
//
// fastest (the default) chooses by the delay of the URL tests, as before. loss chooses by
// the delay weighed by the loss loss probes counted (urltest.LossProbe): the members it may
// switch to and the member in use are probed once a loss_interval with LossProbeSmall bytes,
// and a member the group would switch to without a fresh count first with LossProbeLarge.
// balance spreads the connections over the best members by their source address
// (urltest_balance.go), leaving out a member that loses more than loss_threshold percent.
//
// The weight is the price of a page of report 02 of the stand: a page takes about
// 59 + 4.85·RTT + p·(155 + 1.2·RTT) ms over a path with RTT ms and a loss of p percent, on
// servers with CUBIC and with BBR alike. A member with the loss p is thus as slow as one
// without loss whose delay is greater by the factor 1 + p·(155/RTT + 1.2)/4.85: a near
// server (RTT 20 ms) with 0.8 % costs what a clean one at 50 ms does.
//
// Loss that all the probed members show (the subscriber's line, not a server) does not
// move the choice: the least loss among them is taken off each one's.

const (
	modeFastest = "fastest"
	modeLoss    = "loss"
	modeBalance = "balance"
)

const (
	// defaultLossInterval is how often the members a group may use are probed.
	defaultLossInterval = 30 * time.Minute
	// defaultLossThreshold is the loss, in percent, above which balance leaves a member out.
	defaultLossThreshold = 1.0
	// lossCandidates is how many members besides the one in use loss probes once an interval.
	lossCandidates = 3
	// lossMinSegments is the least segments a window needs to decide by: about one large
	// probe, or a few hours of small ones.
	lossMinSegments = 700
	// lossCommonMembers is how many members with a count it takes to tell the loss of the
	// line from the loss of a server: a rule of two servers is common
	lossCommonMembers = 2
	// lossNotCountedRest is how long a member whose probe could not count is not probed.
	lossNotCountedRest = 6 * time.Hour
)

// lossProbeSlot lets one loss probe run at a time in the process: two at once would share
// the line and the window each sees.
var lossProbeSlot = make(chan struct{}, 1)

// lossOptions are the options of the modes loss and balance.
type lossOptions struct {
	link        string
	interval    time.Duration
	threshold   float64
	balanceSize int
	balanceIdle time.Duration
}

// groupMode checks the mode options and fills the defaults.
func groupMode(mode string, link string, interval time.Duration, threshold float64, balanceSize int, balanceIdle time.Duration) (string, lossOptions, error) {
	options := lossOptions{link: link, interval: interval, threshold: threshold, balanceSize: balanceSize, balanceIdle: balanceIdle}
	switch mode {
	case "", modeFastest:
		return modeFastest, options, nil
	case modeLoss, modeBalance:
	default:
		return "", options, E.New("unknown mode: ", mode)
	}
	if link == "" {
		return "", options, E.New("mode ", mode, " needs loss_url")
	}
	if err := checkDownloadLink("loss_url", link); err != nil {
		return "", options, err
	}
	if options.interval == 0 {
		options.interval = defaultLossInterval
	} else if options.interval < time.Minute {
		return "", options, E.New("loss_interval must be at least 1m")
	}
	if options.threshold == 0 {
		options.threshold = defaultLossThreshold
	} else if options.threshold < 0 || options.threshold > 100 {
		return "", options, E.New("loss_threshold must be a percentage")
	}
	if options.balanceSize == 0 {
		options.balanceSize = defaultBalanceSize
	} else if options.balanceSize < 0 || options.balanceSize > maxBalanceSize {
		return "", options, E.New("balance_size must be from 1 to ", maxBalanceSize)
	}
	if options.balanceIdle == 0 {
		options.balanceIdle = defaultBalanceIdle
	} else if options.balanceIdle < 0 {
		return "", options, E.New("balance_idle must be positive")
	}
	return mode, options, nil
}

// weighDelay is delay weighed by a loss of percent over a path with the RTT rtt.
func weighDelay(delay uint16, percent float64, rtt time.Duration) uint16 {
	if percent <= 0 {
		return delay
	}
	milliseconds := float64(rtt) / float64(time.Millisecond)
	if milliseconds < 5 {
		milliseconds = 5
	}
	weighed := float64(delay) * (1 + percent*(155/milliseconds+1.2)/4.85)
	if weighed > 65535 {
		return 65535
	}
	return uint16(weighed)
}

// memberLoss is what the probes of a member say, for a selection.
type memberLoss struct {
	percent float64 // over the window decided by
	excess  float64 // less the loss of the line
	rtt     time.Duration
	known   bool
}

// lossView is the loss of the members at one moment: what a selection weighs by.
type lossView map[string]memberLoss

// lossView reads the loss of the outbounds; nil in the mode fastest.
func (g *URLTestGroup) lossView() lossView {
	if g.mode == modeFastest {
		return nil
	}
	now := time.Now()
	view := make(lossView)
	floor, counted := 0.0, 0
	for _, member := range g.outbounds {
		tag := group.RealTag(member, N.NetworkTCP)
		window, known := g.history.LossOfWindow(tag, now, lossMinSegments)
		if !known {
			continue
		}
		loss := memberLoss{percent: window.Rate(), rtt: g.history.LossRTT(tag, now), known: true}
		if counted == 0 || loss.percent < floor {
			floor = loss.percent
		}
		counted++
		view[tag] = loss
	}
	for tag, loss := range view {
		loss.excess = loss.percent
		if counted >= lossCommonMembers {
			loss.excess -= floor
		}
		view[tag] = loss
	}
	return view
}

// delay is the delay of a member a selection compares: weighed by its loss in the mode loss.
func (v lossView) delay(tag string, history *adapter.URLTestHistory) uint16 {
	loss, known := v[tag]
	if !known || loss.excess <= 0 {
		return history.Delay
	}
	rtt := loss.rtt
	if rtt == 0 {
		// no RTT of its own: a URL test takes a few round trips
		rtt = time.Duration(history.Delay) * time.Millisecond / 3
	}
	return weighDelay(history.Delay, loss.excess, rtt)
}

// memberAlive tells whether a member may carry connections: it has a test result and has
// not failed the download test since.
func (g *URLTestGroup) memberAlive(member adapter.Outbound) bool {
	tag := group.RealTag(member, N.NetworkTCP)
	history := g.history.LoadURLTestHistory(tag)
	if history == nil {
		return false
	}
	frozenAt, isFrozen := g.frozen.Load()[tag]
	return !isFrozen || history.Time.After(frozenAt)
}

// rankedOutbounds returns the outbounds that may carry connections of the network, the
// fastest first by the delay a selection compares, with that delay.
func (g *URLTestGroup) rankedOutbounds(network string, view lossView) ([]adapter.Outbound, []uint16) {
	type ranked struct {
		member adapter.Outbound
		delay  uint16
	}
	var list []ranked
	for _, member := range g.outbounds {
		if !slices.Contains(member.Network(), network) || !g.memberAlive(member) {
			continue
		}
		tag := group.RealTag(member, network)
		history := g.history.LoadURLTestHistory(tag)
		if history == nil {
			continue
		}
		list = append(list, ranked{member, view.delay(tag, history)})
	}
	slices.SortStableFunc(list, func(a, b ranked) int {
		return int(a.delay) - int(b.delay)
	})
	members := make([]adapter.Outbound, len(list))
	delays := make([]uint16, len(list))
	for i, item := range list {
		members[i], delays[i] = item.member, item.delay
	}
	return members, delays
}

// lossRest is how long after a probe of a member the next one waits: the interval, a little
// early since the rounds that bring the probes come once a URL test interval, but never less
// than half of it (a URL test interval longer than the loss interval would make a member due
// at every round, and two groups probe it back to back).
func (g *URLTestGroup) lossRest() time.Duration {
	return max(g.loss.interval-g.interval/2, g.loss.interval/2)
}

// lossResting tells whether a member is not to be probed now: its probe could not count for
// want of a connection of its own lately, or one was made (counted or failed) within the rest.
func (g *URLTestGroup) lossResting(tag string) bool {
	if notCounted := g.history.LossNotCounted(tag); !notCounted.IsZero() && time.Since(notCounted) < lossNotCountedRest {
		return true
	}
	last, _ := g.history.LossAttempt(tag)
	return !last.IsZero() && time.Since(last) < g.lossRest()
}

// lossDue tells whether a member is to be probed now.
func (g *URLTestGroup) lossDue(tag string) bool {
	return !g.lossResting(tag)
}

// needsSwitchProbe tells whether a member the group would switch to is probed first: it can
// be counted, no probe before a switch to it ran within the rest (one that counted too little
// to decide by, a slow path cut by the time limit, would be made again at every selection),
// no probe of it failed within the rest (a URL that answers a status through it would hold it
// back for good), and it has no count to decide by fresher than the interval.
func (g *URLTestGroup) needsSwitchProbe(tag string) bool {
	if notCounted := g.history.LossNotCounted(tag); !notCounted.IsZero() && time.Since(notCounted) < lossNotCountedRest {
		return false
	}
	if started, probed := g.switchProbed.Load(tag); probed && time.Since(started.(time.Time)) < g.lossRest() {
		return false
	}
	if last, failures := g.history.LossAttempt(tag); failures > 0 && time.Since(last) < g.lossRest() {
		return false
	}
	sample, exists := g.history.LastLossSample(tag)
	if !exists || time.Since(sample.At) >= g.loss.interval {
		return true
	}
	_, known := g.history.LossOfWindow(tag, time.Now(), lossMinSegments)
	return !known
}

// lossSlotWait bounds how long a probe waits for the probes of other groups.
const lossSlotWait = 30 * time.Second

// probeLoss runs a loss probe of size bytes through member and keeps what it counted; it
// reports whether a count was kept. A probe that kept none is recorded: the next one waits
// the rest, and only the first failure in a row is a warning.
func (g *URLTestGroup) probeLoss(tag string, member adapter.Outbound, size int64, periodic bool) bool {
	wait, cancelWait := context.WithTimeout(g.ctx, lossSlotWait)
	select {
	case lossProbeSlot <- struct{}{}:
		cancelWait()
	case <-wait.Done():
		cancelWait()
		return false
	}
	defer func() { <-lossProbeSlot }()
	if periodic && !g.lossDue(tag) {
		// another group probed it while this one waited
		return false
	}
	// the probe's own time, after the wait: a megabyte at the window of the probe over a far
	// path takes most of it
	ctx, cancel := context.WithTimeout(g.ctx, urltest.LossProbeTimeout+5*time.Second)
	defer cancel()
	// a new connection to the first server of the member, like a URL test (probes)
	if probes.waitHop(ctx, firstHop(g.outbound, member)) != nil {
		return false
	}
	start := time.Now()
	sample, err := urltest.LossProbe(ctx, g.loss.link, size, member)
	if g.ctx.Err() != nil {
		// the group was closed or replaced: after a swap the tag may be another outbound's
		return false
	}
	switch {
	case err == nil:
		g.history.StoreLossSample(tag, sample)
		g.logger.Debug("outbound ", tag, " loss probe: ", sample.Lost, " of ", sample.Segments, " segments lost, ",
			sample.Reordered, " bytes reordered, RTT ", sample.RTT.Milliseconds(), "ms, ", sample.Received, " bytes in ",
			sample.Elapsed.Milliseconds(), "ms")
		return true
	case errors.Is(err, urltest.ErrLossNotOwnConnection):
		g.history.StoreLossNotCounted(tag, time.Now())
		g.logger.Info("outbound ", tag, " loss probe could not count, the member is chosen by its delay: ", err)
	case g.networkChangedSince(start):
		// cut by a change of the network: says nothing, and is made again at the next round
	default:
		if g.history.StoreLossFailure(tag, time.Now()) == 1 {
			g.logger.Warn("outbound ", tag, " loss probe: ", err)
		} else {
			g.logger.Debug("outbound ", tag, " loss probe: ", err)
		}
	}
	return false
}

// startSwitchProbe probes, in the background, a member the group would switch to, and asks
// for a selection once the probe is done: the selection does not wait for it (a megabyte
// may take half a minute, and a member in use that goes down meanwhile is left at once). One
// probe of a member at a time.
func (g *URLTestGroup) startSwitchProbe(tag string, member adapter.Outbound) {
	if _, running := g.switchProbes.LoadOrStore(tag, struct{}{}); running {
		return
	}
	g.switchProbed.Store(tag, time.Now())
	go func() {
		defer g.switchProbes.Delete(tag)
		g.probeLoss(tag, member, urltest.LossProbeLarge, false)
		if g.ctx.Err() == nil {
			g.requestUpdateCheck()
		}
	}()
}

// lossTargets are the members the periodic probes keep counted: in the mode loss the one
// in use and the lossCandidates best others, in the mode balance the members of the
// balance and two more.
func (g *URLTestGroup) lossTargets() []adapter.Outbound {
	ranked, _ := g.rankedOutbounds(N.NetworkTCP, g.lossView())
	var targets []adapter.Outbound
	switch g.mode {
	case modeLoss:
		current := g.selectedOutboundTCP.Load()
		if current != nil && !g.isFallback(current) && g.memberAlive(current) {
			targets = append(targets, current)
		}
		for _, member := range ranked {
			if len(targets) >= lossCandidates+1 {
				break
			}
			if member != current {
				targets = append(targets, member)
			}
		}
	case modeBalance:
		targets = ranked[:min(len(ranked), g.loss.balanceSize+2)]
	}
	return targets
}

// lossRound runs the periodic probes of the members that are due, after a round, in the
// background: one round of probes at a time. A count kept asks for a selection.
func (g *URLTestGroup) lossRound() {
	if g.mode == modeFastest || g.closed.Load() || !g.lossRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer g.lossRunning.Store(false)
		counted := false
		for _, member := range g.lossTargets() {
			if g.ctx.Err() != nil || g.networkPaused() {
				return
			}
			tag := group.RealTag(member, N.NetworkTCP)
			if !g.lossDue(tag) {
				continue
			}
			if g.probeLoss(tag, member, urltest.LossProbeSmall, true) {
				counted = true
			}
		}
		if counted {
			g.requestUpdateCheck()
		}
	}()
}

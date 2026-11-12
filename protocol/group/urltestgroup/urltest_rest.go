package urltestgroup

import (
	"time"

	N "github.com/sagernet/sing/common/network"
)

// A balance at rest (podkop-engine).
//
// The balance of a group is the best of its members at each selection, and a member that comes in is
// download tested. The best three of ten servers with about the same delay are others at almost every
// round, so a balance costs 64 KiB a round, whether anything goes through the group or not. A group
// that is not in use (urltest_use.go: the fallback of another, mostly) has no balance: it keeps its
// plain choice, as the mode fastest does, download tested as any choice is before a switch to it.
//
// The balance is made when the group comes into use, from the delays the tests found and the counts
// of loss that are kept, before the first connection is dialed: it and those that come with it are
// spread as any. What the first connections do not have is the download test of their members, which
// begins with the first of them: a member that fails it leaves the balance, and its devices go to
// another at their next connection. A member that passed it within the loss_interval has no need of
// it, so a group that is in use now and then is not download tested time after time; nor is a member
// that left the balance and comes back. Before a round has tested the members there is no balance to
// make: the first connections go by the plain choice, until the round's selection makes it.

// startUse records a use at now, and tells whether the group comes into use by it. Who finds the
// group in use finds its balance.
func (g *URLTestGroup) startUse(now time.Time) bool {
	if g.usedLately(now) {
		g.lastUse.Store(now)
		return false
	}
	g.useStart.Lock()
	defer g.useStart.Unlock()
	if g.usedLately(now) {
		// another connection brought the group into use
		g.lastUse.Store(now)
		return false
	}
	g.startBalance()
	g.lastUse.Store(now)
	return true
}

func (g *URLTestGroup) usedLately(now time.Time) bool {
	last := g.lastUse.Load()
	return !last.IsZero() && now.Sub(last) <= g.idleTimeout
}

// startBalance makes the balance of a group that comes into use. The caller holds useStart.
func (g *URLTestGroup) startBalance() {
	b := g.balance.Load()
	if g.mode != modeBalance || b == nil || !g.roundDone.Load() {
		return
	}
	view := g.lossView()
	tcp := g.balanceMembers(N.NetworkTCP, view, nil)
	udp := g.balanceMembers(N.NetworkUDP, view, nil)
	if g.putBalance(b, tcp, udp, tcp) {
		g.history.NotifyUpdated()
	}
}

// restBalance takes the members out of the balance of a group that is not in use, and tells whether
// it is not. The connections its devices have go on.
func (g *URLTestGroup) restBalance(b *balancer) bool {
	g.useStart.Lock()
	if g.inUse() {
		g.useStart.Unlock()
		return false
	}
	b.access.Lock()
	had := g.balance.Load() == b && len(b.tcp)+len(b.udp) > 0
	if had {
		b.tcp, b.udp, b.unchecked = nil, nil, nil
	}
	b.access.Unlock()
	g.useStart.Unlock()
	if had {
		g.logger.Debug("no connections for ", g.idleTimeout, ", the balance rests")
		g.history.NotifyUpdated()
	}
	return true
}

// downloadPassed tells whether a member has passed the download test within the loss_interval, and
// is not frozen since.
func (g *URLTestGroup) downloadPassed(tag string) bool {
	if _, isFrozen := g.frozen.Load()[tag]; isFrozen {
		return false
	}
	result, known := g.history.LoadDownloadResult(tag)
	return known && !result.Stopped && time.Since(result.At) < g.loss.interval
}

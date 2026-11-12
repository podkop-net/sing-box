package urltestgroup

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/common/urltest"
)

// When a group is in use (podkop-engine).
//
// A loss probe is traffic: in the modes loss and balance a group of four members downloads a
// megabyte of them every loss_interval, and one more before a switch. It is worth that for a group
// that carries connections. A group that is the fallback of another carries none while the group
// above has an outbound that answers, but it is tested with it, round after round, so that its
// choice is a tested one at the moment it is needed (urlTestMembers of the group above): the
// probes that followed each round of it were spent on a choice nobody used.
//
// So the loss probes run only while the group is in use: from a connection dialed through it, or
// attached to it by the router, until idle_timeout without another. The dials of tests are not a
// use (urltest.TestFromContext): the URL test of a nested group out of turn, the download test
// before a switch to it and the loss probe of the group above all dial through it as a connection
// would. A group that is not in use is tested and selects by its URL tests and its download test
// as before, by the counts of loss it has from the time it was in use, as long as they are kept.
// The first choice of a group that comes into use goes by the delays, as that of a group that was
// just started; its probes start at once and change it at the selection that follows them
// (lossProbeSize).

// used records a use of the group. One that comes into use starts its loss probes, when a round of
// this interval has tested the members; otherwise the round that comes next starts them (Touch
// begins one for a group that was idle).
func (g *URLTestGroup) used() {
	now := time.Now()
	if !g.startUse(now) {
		return
	}
	g.usedSince.Store(now)
	// not before a round has tested the members: the best of those tested so far are not the best
	if g.roundDone.Load() && now.Sub(g.epoch)-time.Duration(g.lastRound.Load()) <= g.interval {
		g.lossRound()
	}
	if g.mode == modeBalance && g.roundDone.Load() {
		// the download tests of the members startUse put in the balance
		g.requestUpdateCheck()
	}
}

// usedBy is used for a dial with ctx, unless it is the dial of a test.
func (g *URLTestGroup) usedBy(ctx context.Context) {
	if !urltest.TestFromContext(ctx) {
		g.used()
	}
}

// inUse tells whether the group carries connections (used).
func (g *URLTestGroup) inUse() bool {
	last := g.lastUse.Load()
	return !last.IsZero() && time.Since(last) <= g.idleTimeout
}

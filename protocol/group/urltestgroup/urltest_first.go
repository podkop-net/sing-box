package urltestgroup

import (
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
)

// The first loss probes of a group that comes into use (podkop-engine).
//
// A periodic probe is too small to decide by: the counts of a member sum up to lossMinSegments
// after four of them, hours at the default interval. A group that carried nothing has no counts, and
// the first connections may come because another group has fallen back on it: a loss that decides
// two hours later decides nothing. So the members a group probes in the first loss_interval of a
// use and that have no count to decide by are probed with LossProbeLarge, which decides alone, and a
// selection follows each of these probes. They are as many, and come one after another, as the
// periodic probes do. A member has one large probe in a loss_interval at most, so a group that is in
// use now and then pays for its members once, and a member whose counts are kept from an earlier use,
// or cannot be counted, is probed as ever.

// lossProbeSize is the size of a periodic probe of a member.
func (g *URLTestGroup) lossProbeSize(tag string) int64 {
	now := time.Now()
	if now.Sub(g.usedSince.Load()) >= g.loss.interval || !g.history.LossNotCounted(tag).IsZero() {
		return urltest.LossProbeSmall
	}
	if started, probed := g.switchProbed.Load(tag); probed && now.Sub(started.(time.Time)) < g.loss.interval {
		if last, _ := g.history.LossAttempt(tag); !last.Before(started.(time.Time)) {
			return urltest.LossProbeSmall
		}
		// one before a switch that was given up for want of its turn
	}
	if _, known := g.history.LossOfWindow(tag, now, lossMinSegments); known {
		return urltest.LossProbeSmall
	}
	return urltest.LossProbeLarge
}

// firstLossProbe runs a large probe of a member and asks for a selection once it is done. One
// before a switch to the member that runs does as well, and is not made twice; a selection that
// comes meanwhile takes this one for it.
func (g *URLTestGroup) firstLossProbe(tag string, member adapter.Outbound) {
	started := time.Now()
	if _, running := g.switchProbes.LoadOrStore(tag, started); running {
		return
	}
	g.probeLoss(tag, member, urltest.LossProbeLarge, true)
	if last, _ := g.history.LossAttempt(tag); !last.Before(started) {
		// one that was made: not one that had no turn
		g.switchProbed.Store(tag, started)
	}
	g.switchProbes.CompareAndDelete(tag, started)
	if g.ctx.Err() == nil {
		g.requestUpdateCheck()
	}
}

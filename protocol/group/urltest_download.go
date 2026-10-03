package group

import (
	"context"
	"errors"
	"maps"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

// The download test (podkop-engine).
//
// The URL test asks for a few hundred bytes, and a server behind a DPI that freezes every
// connection after ~16 KB passes it with a good delay: the group selects a member through
// which nothing but small requests works. So before the group switches to a member, it
// downloads urltest.DownloadTestSize through it (urltest.DownloadTest). A member whose
// download stopped on the way is passed over, and tried again once its next test result
// has come, which the periodic test brings: once an interval while it stays the better
// choice. A test that could not run (the URL answers with a status, a short body, nothing)
// says nothing about the member and holds it back from nothing; it is logged, as the URL
// is the user's. The member in use is tested only when it was taken as the last resort,
// frozen: a connection that freezes only once it carries data is not seen here.
//
// The test URL comes from SING_BOX_URLTEST_DOWNLOAD_URL (the init script sets it from
// /etc/config/sing-box); without it nothing changes.

var (
	downloadTestLink    = os.Getenv("SING_BOX_URLTEST_DOWNLOAD_URL")
	downloadTestTimeout = C.TCPTimeout
)

// selectTested chooses the TCP member as Select does, except that a member the group would
// switch to first passes the download test. When no candidate passes, a current member
// with a test result stays; without one, the plain choice is taken: a member frozen after
// 16 KB carries small requests, a dead one none.
func (g *URLTestGroup) selectTested() (adapter.Outbound, bool) {
	if g.downloadLink == "" {
		return g.Select(N.NetworkTCP)
	}
	current := g.selectedOutboundTCP.Load()
	tried := make(map[string]bool)
	for {
		candidate, exists := g.selectAmong(N.NetworkTCP, g.skipFrozen(tried))
		if candidate == nil || !exists {
			break
		}
		tag := RealTag(candidate)
		if candidate == current {
			if _, wasFrozen := g.frozen.Load()[tag]; !wasFrozen {
				break
			}
			// the member in use was taken as the last resort, frozen, and a newer result
			// made it a candidate again: it is tested, or it would keep out, by the
			// tolerance, a member that has recovered meanwhile
		}
		if !g.downloadStopped(tag, candidate) {
			g.setFrozen(tag, time.Time{})
			return candidate, true
		}
		g.setFrozen(tag, time.Now())
		tried[tag] = true
	}
	if current != nil && g.history.LoadURLTestHistory(RealTag(current)) != nil {
		return current, true
	}
	return g.Select(N.NetworkTCP)
}

// selectionPending reports whether the selected member has lost its test result while the
// download check may keep the next selection waiting (one download test per candidate):
// connections then go by the plain choice instead of a member known to be down.
func (g *URLTestGroup) selectionPending(selected adapter.Outbound) bool {
	return g.downloadLink != "" && g.history.LoadURLTestHistory(RealTag(selected)) == nil
}

// selectUDP chooses the UDP member as Select does, passing over the members frozen for TCP.
func (g *URLTestGroup) selectUDP() (adapter.Outbound, bool) {
	if candidate, exists := g.selectAmong(N.NetworkUDP, g.skipFrozen(nil)); exists {
		return candidate, true
	}
	return g.Select(N.NetworkUDP)
}

// skipFrozen passes over the members tried in this selection and those that failed the
// download test and have no newer test result.
func (g *URLTestGroup) skipFrozen(tried map[string]bool) func(tag string, history *adapter.URLTestHistory) bool {
	frozen := g.frozen.Load()
	return func(tag string, history *adapter.URLTestHistory) bool {
		if tried[tag] {
			return true
		}
		frozenAt, isFrozen := frozen[tag]
		return isFrozen && !history.Time.After(frozenAt)
	}
}

// setFrozen records when a member failed the download test, or forgets it (zero time).
// The map is replaced, not changed: selections read it without a lock.
func (g *URLTestGroup) setFrozen(tag string, at time.Time) {
	frozen := maps.Clone(g.frozen.Load())
	if frozen == nil {
		frozen = make(map[string]time.Time)
	}
	if at.IsZero() {
		delete(frozen, tag)
	} else {
		frozen[tag] = at
	}
	g.frozen.Store(frozen)
}

// downloadStopped runs the download test through member and reports whether the download
// stopped on the way, the one failure that is the member's.
func (g *URLTestGroup) downloadStopped(tag string, member adapter.Outbound) bool {
	ctx, cancel := context.WithTimeout(g.ctx, downloadTestTimeout)
	defer cancel()
	start := time.Now()
	received, elapsed, err := urltest.DownloadTest(ctx, g.downloadLink, member)
	switch {
	case err == nil:
		g.logger.Debug("outbound ", tag, " download test: ", received, " bytes in ", elapsed.Milliseconds(), "ms")
		g.memberTestPassed(tag, start)
	case errors.Is(err, urltest.ErrDownloadStopped):
		g.logger.Warn("outbound ", tag, " download test: ", err)
		return true
	default:
		g.logger.Warn("outbound ", tag, " download test could not run, the member is not held back: ", err)
	}
	return false
}

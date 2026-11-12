package urltestgroup

import (
	"context"
	"errors"
	"github.com/sagernet/sing-box/protocol/group"
	"maps"
	"net/url"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
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
// The test URL is the group's download_url; a group without the option takes
// SING_BOX_URLTEST_DOWNLOAD_URL (the init script sets it from /etc/config/sing-box), and an
// empty download_url turns the test off for the group. Without either nothing changes.
// An environment value the test could not use is no reason to refuse the start: the
// group warns once and goes without the test.

var (
	downloadTestLink    = os.Getenv("SING_BOX_URLTEST_DOWNLOAD_URL")
	downloadTestTimeout = C.TCPTimeout
)

// groupDownloadLink is the download test URL of a group with the download_url option
// downloadURL (nil when absent). A URL the test could not use is a configuration error,
// which sing-box check reports: an http or https URL with a host.
func groupDownloadLink(downloadURL *string) (string, error) {
	if downloadURL == nil {
		return downloadTestLink, nil
	}
	link := *downloadURL
	if link == "" {
		return "", nil
	}
	err := checkDownloadLink("download_url", link)
	if err != nil {
		return "", err
	}
	return link, nil
}

// checkDownloadLink tells whether the download test can use link, the value of the
// setting name.
func checkDownloadLink(name string, link string) error {
	linkURL, err := url.Parse(link)
	if err != nil {
		return E.Cause(err, "parse ", name)
	}
	if (linkURL.Scheme != "http" && linkURL.Scheme != "https") || linkURL.Hostname() == "" {
		return E.New(name, ": an http or https URL with a host expected: ", link)
	}
	return nil
}

// selectTested chooses the TCP member as Select does, except that a member the group would
// switch to first passes the download test, and in the mode loss is first probed for loss
// when it has no fresh count (podkop-engine): the probe runs in the background and the member
// in use stays meanwhile; the probe asks for a selection when it is done. When no candidate
// passes, a current member with a test result stays; without one, the plain choice is taken:
// a member frozen after 16 KB carries small requests, a dead one none.
func (g *URLTestGroup) selectTested() (adapter.Outbound, bool) {
	if g.downloadLink == "" && g.mode != modeLoss {
		return g.Select(N.NetworkTCP)
	}
	current := g.selectedOutboundTCP.Load()
	// a member in use that is down is left at once, without a probe, as before
	currentAlive := current != nil && !g.isFallback(current) && g.memberAlive(current)
	tried := make(map[string]bool)
	downloaded := make(map[string]bool)
	for {
		candidate, exists := g.selectAmong(N.NetworkTCP, g.skipFrozen(tried))
		if candidate == nil || !exists {
			break
		}
		if candidate.Type() == C.TypeBlock {
			// a block fallback downloads nothing: it refuses (podkop-engine)
			return candidate, true
		}
		tag := group.RealTag(candidate, N.NetworkTCP)
		if candidate == current {
			if _, wasFrozen := g.frozen.Load()[tag]; !wasFrozen {
				break
			}
			// the member in use was taken as the last resort, frozen, and a newer result
			// made it a candidate again: it is tested, or it would keep out, by the
			// tolerance, a member that has recovered meanwhile
		}
		if g.downloadLink != "" && !downloaded[tag] {
			start := time.Now()
			if g.downloadStopped(tag, candidate) {
				// frozen as of the start of the test: a URL test that passed while the
				// download ran (the round forced by a network change, which also cut this
				// download) is a newer result and brings the member back
				g.setFrozen(tag, start)
				tried[tag] = true
				continue
			}
			g.setFrozen(tag, time.Time{})
			downloaded[tag] = true
		}
		if g.mode == modeLoss && currentAlive && candidate != current && g.needsSwitchProbe(tag) {
			// the switch waits for a count of the candidate: the member in use stays until the
			// probe is done, and the selection then runs again with what it counted
			g.startSwitchProbe(tag, candidate)
			break
		}
		return candidate, true
	}
	if current != nil && g.history.LoadURLTestHistory(group.RealTag(current, N.NetworkTCP)) != nil {
		return current, true
	}
	return g.Select(N.NetworkTCP)
}

// selectionPending reports whether the selected member has lost its test result while the
// download check may keep the next selection waiting (one download test per candidate):
// connections then go by the plain choice instead of a member known to be down.
func (g *URLTestGroup) selectionPending(selected adapter.Outbound) bool {
	return g.selectionMayWait() && g.history.LoadURLTestHistory(group.RealTag(selected, N.NetworkTCP)) == nil
}

// selectionMayWait tells whether a selection may wait for a test of a candidate: the download
// test (a loss probe runs in the background).
func (g *URLTestGroup) selectionMayWait() bool {
	return g.downloadLink != ""
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
	// a new connection to the first server of the member, like a URL test (probes)
	if probes.waitHop(ctx, firstHop(g.outbound, member)) != nil {
		return false
	}
	start := time.Now()
	received, elapsed, err := urltest.DownloadTest(ctx, g.downloadLink, member)
	switch {
	case err == nil:
		g.logger.Debug("outbound ", tag, " download test: ", received, " bytes in ", elapsed.Milliseconds(), "ms")
		g.history.StoreDownloadResult(tag, urltest.DownloadResult{At: time.Now(), Received: received})
		g.memberTestPassed(tag, start)
	case errors.Is(err, urltest.ErrDownloadStopped):
		g.logger.Warn("outbound ", tag, " download test: ", err)
		// a download cut by the close of the group or a change of the network says nothing of the
		// member, and after a swap the tag may be another outbound's
		if g.ctx.Err() == nil && !g.networkChangedSince(start) {
			g.history.StoreDownloadResult(tag, urltest.DownloadResult{At: time.Now(), Received: received, Stopped: true})
		}
		return true
	default:
		g.logger.Warn("outbound ", tag, " download test could not run, the member is not held back: ", err)
	}
	return false
}

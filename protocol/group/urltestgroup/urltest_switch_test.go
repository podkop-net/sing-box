package urltestgroup

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

// newHeldLossURL serves the loss URL; a probe is answered once release is called.
func newHeldLossURL(t *testing.T, status int) (link string, requests *atomic.Int32, release func()) {
	gate := make(chan struct{})
	requests = new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		select {
		case <-gate:
		case <-r.Context().Done():
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(lossProbeBody))
		w.Write(make([]byte, lossProbeBody))
	}))
	t.Cleanup(server.Close)
	released := false
	release = func() {
		if !released {
			released = true
			close(gate)
		}
	}
	t.Cleanup(release)
	return server.URL, requests, release
}

// A selection that runs while a probe before a switch does (a group gets selections from its own
// rounds, those of the group above and the connections that fail) waits for the probe as the first
// did. The probe's end, whatever came of it, lets the switch go.
func TestSwitchProbeWaitedFor(t *testing.T) {
	for name, status := range map[string]int{"counted": http.StatusOK, "failed": http.StatusForbidden} {
		t.Run(name, func(t *testing.T) {
			link, requests, release := newHeldLossURL(t, status)
			a, b := newTestMember(C.TypeSOCKS, "a", dialProbe), newTestMember(C.TypeSOCKS, "b", dialProbe)
			_, group := newModeGroup(t, modeLoss, members(a, b), map[string]uint16{"a": 100, "b": 300}, nil)
			group.loss.link = link
			setResult(group, "b", 20)
			for range 3 {
				group.performUpdateCheck()
				tcp, _ := selectedTags(group)
				require.Equal(t, "a", tcp, "the probe of b runs")
				require.True(t, group.switchProbeRuns("b"))
				require.Eventually(t, func() bool { return requests.Load() == 1 }, 10*time.Second, 10*time.Millisecond)
			}
			release()
			waitChoice(t, group, "b")
			require.Equal(t, int32(1), requests.Load(), "one probe for all of them")
			require.False(t, group.switchProbeRuns("b"))
		})
	}
}

// The selections that wait for the probe make no download test of their own: the one that began it
// made one, and the one after it makes the one before the switch.
func TestSwitchProbeOneDownloadTest(t *testing.T) {
	var downloads atomic.Int32
	download := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloads.Add(1)
		w.Header().Set("Content-Length", fmt.Sprint(urltest.DownloadTestSize))
		w.Write(make([]byte, urltest.DownloadTestSize))
	}))
	t.Cleanup(download.Close)
	link, requests, release := newHeldLossURL(t, http.StatusOK)
	a, b := newTestMember(C.TypeSOCKS, "a", dialProbe), newTestMember(C.TypeSOCKS, "b", dialProbe)
	_, group := newModeGroup(t, modeLoss, members(a, b), map[string]uint16{"a": 100, "b": 300}, nil)
	group.loss.link, group.downloadLink = link, download.URL
	setResult(group, "b", 20)
	for range 4 {
		group.performUpdateCheck()
	}
	require.Eventually(t, func() bool { return requests.Load() == 1 }, 10*time.Second, 10*time.Millisecond)
	tcp, _ := selectedTags(group)
	require.Equal(t, "a", tcp)
	require.Equal(t, int32(1), downloads.Load())
	release()
	waitChoice(t, group, "b")
	require.Equal(t, int32(2), downloads.Load())
}

// The member in use that goes down while the probe runs is left at once.
func TestSwitchProbeMemberInUseDown(t *testing.T) {
	link, requests, _ := newHeldLossURL(t, http.StatusOK)
	a, b := newTestMember(C.TypeSOCKS, "a", dialProbe), newTestMember(C.TypeSOCKS, "b", dialProbe)
	_, group := newModeGroup(t, modeLoss, members(a, b), map[string]uint16{"a": 100, "b": 300}, nil)
	group.loss.link = link
	setResult(group, "b", 20)
	group.performUpdateCheck()
	require.Eventually(t, func() bool { return requests.Load() == 1 }, 10*time.Second, 10*time.Millisecond)
	setResult(group, "a", 0)
	group.performUpdateCheck()
	tcp, _ := selectedTags(group)
	require.Equal(t, "b", tcp)
}

// A probe that does not end (a dial that ignores its context) holds back a switch no longer than a
// probe may take, and does not keep the next one from running.
func TestSwitchProbeStuck(t *testing.T) {
	newStuck := func(rest bool) (*URLTestGroup, *atomic.Int32, time.Time) {
		link, requests, release := newHeldLossURL(t, http.StatusOK)
		release()
		a, b := newTestMember(C.TypeSOCKS, "a", dialProbe), newTestMember(C.TypeSOCKS, "b", dialProbe)
		_, group := newModeGroup(t, modeLoss, members(a, b), map[string]uint16{"a": 100, "b": 300}, nil)
		group.loss.link = link
		stuck := time.Now().Add(-lossSlotWait - lossProbeTime - time.Second)
		if rest {
			stuck = stuck.Add(-group.lossRest())
		}
		group.switchProbes.Store("b", stuck)
		group.switchProbed.Store("b", stuck)
		setResult(group, "b", 20)
		group.performUpdateCheck()
		return group, requests, stuck
	}
	// within the rest: the switch goes without another probe
	group, requests, _ := newStuck(false)
	tcp, _ := selectedTags(group)
	require.Equal(t, "b", tcp)
	require.Zero(t, requests.Load())

	// past it: another probe runs, and its end lets the switch go
	group, requests, stuck := newStuck(true)
	tcp, _ = selectedTags(group)
	require.Equal(t, "a", tcp)
	waitChoice(t, group, "b")
	require.Equal(t, int32(1), requests.Load())
	// the end of the stuck one is not the end of a later one
	group.switchProbes.Store("b", time.Now())
	group.switchProbes.CompareAndDelete("b", stuck)
	require.True(t, group.switchProbeRuns("b"))
}

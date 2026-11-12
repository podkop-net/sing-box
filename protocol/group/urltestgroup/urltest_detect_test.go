package urltestgroup

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// The failure of a dial, which takes the result of the member away, is kept with its time.
func TestURLTestRecordsDialFailure(t *testing.T) {
	link, _ := testURL(t, 0)
	dead := newTestMember(C.TypeVLESS, "dead", dialRefused)
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, dead, spare)
	before := time.Now()

	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	require.Nil(t, group.history.LoadURLTestHistory("dead"))
	at, loaded := group.history.LoadURLTestFailure("dead")
	require.True(t, loaded)
	require.False(t, at.Before(before))
	_, loaded = group.history.LoadURLTestFailure("spare")
	require.False(t, loaded)
}

// A round: the member that fails has a failure, and the next test it passes clears that.
func TestURLTestRoundRecordsFailure(t *testing.T) {
	link, _ := testURL(t, 0)
	history := urltest.NewHistoryStorage()
	member := newTestMember(C.TypeVLESS, "m", dialRefused)
	logger := log.NewNOPFactory().Logger()

	URLTestOutbounds(context.Background(), nil, history, logger, []adapter.Outbound{member}, link, time.Minute, true, true)
	_, loaded := history.LoadURLTestFailure("m")
	require.True(t, loaded)

	member.dial = dialWorking
	URLTestOutbounds(context.Background(), nil, history, logger, []adapter.Outbound{member}, link, time.Minute, true, true)
	require.NotNil(t, history.LoadURLTestHistory("m"))
	_, loaded = history.LoadURLTestFailure("m")
	require.False(t, loaded)
}

// lateTimerContext is a context whose deadline has come and whose timer has not closed it yet, as
// any context with a deadline is for a moment: Err is nil.
type lateTimerContext struct {
	context.Context
	deadline time.Time
}

func (c lateTimerContext) Deadline() (time.Time, bool) { return c.deadline, true }

// A test that the deadline of its round cut is no failure of the member, though the context does
// not say so yet (GC-F1: live servers lost their delay and got a failure after a delay test of
// the Clash API), while a failure within the deadline still is one.
func TestURLTestRoundCutIsNoFailure(t *testing.T) {
	link, _ := testURL(t, 0)
	history := urltest.NewHistoryStorage()
	logger := log.NewNOPFactory().Logger()
	member := newTestMember(C.TypeVLESS, "m", dialWorking)
	history.StoreURLTestHistory("m", &adapter.URLTestHistory{Time: time.Now(), Delay: 44})

	// the slot came in the moment after the deadline: the dialer takes the deadline of the
	// context and fails at once with "i/o timeout"
	cut := lateTimerContext{Context: context.Background(), deadline: time.Now().Add(-time.Millisecond)}
	_, err := probeOutbound(cut, link, member)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoError(t, cut.Err())
	URLTestOutbounds(cut, nil, history, logger, []adapter.Outbound{member}, link, time.Minute, true, true)
	require.Equal(t, int32(2), member.dials.Load())
	_, failed := history.LoadURLTestFailure("m")
	require.False(t, failed, "a test the deadline cut is recorded as a failure")
	require.NotNil(t, history.LoadURLTestHistory("m"), "a test the deadline cut took the delay away")

	// a dial under way times out at the deadline of the round
	slow := newTestMember(C.TypeVLESS, "slow", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		deadline, _ := ctx.Deadline()
		time.Sleep(time.Until(deadline))
		return nil, os.ErrDeadlineExceeded
	})
	history.StoreURLTestHistory("slow", &adapter.URLTestHistory{Time: time.Now(), Delay: 44})
	cut = lateTimerContext{Context: context.Background(), deadline: time.Now().Add(50 * time.Millisecond)}
	URLTestOutbounds(cut, nil, history, logger, []adapter.Outbound{slow}, link, time.Minute, true, true)
	_, failed = history.LoadURLTestFailure("slow")
	require.False(t, failed, "a test under way the deadline cut is recorded as a failure")
	require.NotNil(t, history.LoadURLTestHistory("slow"))

	// a member that fails within the deadline has failed
	dead := newTestMember(C.TypeVLESS, "dead", dialRefused)
	history.StoreURLTestHistory("dead", &adapter.URLTestHistory{Time: time.Now(), Delay: 44})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	URLTestOutbounds(ctx, nil, history, logger, []adapter.Outbound{dead}, link, time.Minute, true, true)
	_, failed = history.LoadURLTestFailure("dead")
	require.True(t, failed)
	require.Nil(t, history.LoadURLTestHistory("dead"))
}

// The test that confirms a failure, when the destination may be what failed.
func TestURLTestConfirmRecordsFailure(t *testing.T) {
	link, _ := testURL(t, 0)
	member := newTestMember(C.TypeVLESS, "m", dialRefused)
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	_, group := newTestURLTest(t, link, member, spare)
	require.True(t, group.confirmFailure("m", member))
	waitConfirmed(t, group, "m")
	require.Eventually(t, func() bool {
		_, loaded := group.history.LoadURLTestFailure("m")
		return loaded
	}, 2*time.Second, 5*time.Millisecond)
	require.Nil(t, group.history.LoadURLTestHistory("m"))
}

// What a download test found is kept when it says something of the member: passed or stopped on
// the way. One that could not run leaves nothing.
func TestURLTestDownloadRecords(t *testing.T) {
	shortDownloadTimeout(t)
	full := newDownloadServer(t, "full")
	stall := newDownloadServer(t, "stall")
	short := newDownloadServer(t, "short")
	a := newTestMember(C.TypeVLESS, "a", dialTo(full))
	_, group := newTestURLTest(t, full.URL, a)
	before := time.Now()

	group.downloadLink = full.URL
	require.False(t, group.downloadStopped("full", a))
	result, loaded := group.history.LoadDownloadResult("full")
	require.True(t, loaded)
	require.False(t, result.Stopped)
	require.Equal(t, int64(urltest.DownloadTestSize), result.Received)
	require.False(t, result.At.Before(before))

	stalled := newTestMember(C.TypeVLESS, "stalled", dialTo(stall))
	group.downloadLink = stall.URL
	require.True(t, group.downloadStopped("stalled", stalled))
	result, loaded = group.history.LoadDownloadResult("stalled")
	require.True(t, loaded)
	require.True(t, result.Stopped)
	require.Equal(t, int64(16<<10), result.Received)

	shortMember := newTestMember(C.TypeVLESS, "short", dialTo(short))
	group.downloadLink = short.URL
	require.False(t, group.downloadStopped("short", shortMember))
	_, loaded = group.history.LoadDownloadResult("short")
	require.False(t, loaded)
}

// A download cut by the close of the group or by a change of the network says nothing of the member:
// it is not kept, and the test ends as it did.
func TestURLTestDownloadStoppedByOwnCause(t *testing.T) {
	shortDownloadTimeout(t)
	stall := newDownloadServer(t, "stall")
	member := newTestMember(C.TypeVLESS, "m", dialTo(stall))

	_, group := newTestURLTest(t, stall.URL, member)
	group.downloadLink = stall.URL
	timer := time.AfterFunc(100*time.Millisecond, group.networkReset)
	defer timer.Stop()
	require.True(t, group.downloadStopped("m", member))
	_, loaded := group.history.LoadDownloadResult("m")
	require.False(t, loaded, "the network changed during the test")

	// the network has not changed since: the same stop is the member's
	require.True(t, group.downloadStopped("m", member))
	result, loaded := group.history.LoadDownloadResult("m")
	require.True(t, loaded)
	require.True(t, result.Stopped)

	_, group = newTestURLTest(t, stall.URL, member)
	group.downloadLink = stall.URL
	timer = time.AfterFunc(100*time.Millisecond, group.cancel)
	defer timer.Stop()
	require.True(t, group.downloadStopped("m", member))
	_, loaded = group.history.LoadDownloadResult("m")
	require.False(t, loaded, "the group was closed during the test")
}

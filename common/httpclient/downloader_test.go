package httpclient

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

// testPlan is a plan of the same shape as downloadPlan, a hundred times shorter.
var testPlan = DownloadPlan{Wait: 50 * time.Millisecond, Body: 30 * time.Millisecond, LargeBody: 300 * time.Millisecond, Large: 1000, Most: 3}

func testDownloader(ways ...string) *Downloader {
	downloader := NewDownloader(log.NewNOPFactory().Logger(), ways, map[string]adapter.HTTPTransport{}, nil, nil)
	downloader.Plan = testPlan
	return downloader
}

func accepting(string, any) error { return nil }

// The order: the way that brought the host's last file; the first of the list; the ways that
// brought another host's file, the fastest first; those the URL tests passed, the lowest delay
// first; the unknown ones in list order; those that failed for the host, the oldest failure first.
func TestDownloadMemoryOrder(t *testing.T) {
	memory := NewDownloadMemory()
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory("tested-slow", &adapter.URLTestHistory{Time: time.Now(), Delay: 300})
	history.StoreURLTestHistory("tested-fast", &adapter.URLTestHistory{Time: time.Now(), Delay: 40})
	history.StoreURLTestHistory("failed-old", &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	downloader := NewDownloader(log.NewNOPFactory().Logger(), []string{
		"direct", "unknown-1", "failed-new", "tested-slow", "other-slow", "brought", "failed-old",
		"tested-fast", "other-fast", "unknown-2",
	}, nil, memory, history)
	memory.failed("lists.example", "failed-old")
	time.Sleep(time.Millisecond)
	memory.failed("lists.example", "failed-new")
	memory.brought("other.example", "other-slow", time.Second, 1000)
	memory.brought("other.example", "other-fast", time.Second, 9000)
	memory.brought("lists.example", "brought", time.Second, 1)
	ways, together := downloader.Ways("lists.example")
	require.Equal(t, []string{
		"brought", "direct", "other-fast", "other-slow", "tested-fast", "tested-slow",
		"unknown-1", "unknown-2", "failed-old", "failed-new",
	}, ways)
	require.False(t, together)
}

// The first way of the list stays first when it failed for the host, but the next starts with it;
// a way that brings the host's file again is no longer a failed one.
func TestDownloadMemoryTogether(t *testing.T) {
	downloader := testDownloader("direct", "a", "b")
	downloader.Record("lists.example", "direct", errors.New("reset"), 0, 0)
	ways, together := downloader.Ways("lists.example")
	require.Equal(t, []string{"direct", "a", "b"}, ways)
	require.True(t, together)
	downloader.Record("lists.example", "direct", nil, time.Second, 1)
	_, together = downloader.Ways("lists.example")
	require.False(t, together)
	_, together = downloader.Ways("other.example")
	require.False(t, together)
}

// A way that does not answer has the next one started beside it after Wait; the first result
// accepted wins, the way under way is cancelled, and the host's next download starts with the
// way that brought it.
func TestDownloaderStartsNextWhenSilent(t *testing.T) {
	downloader := testDownloader("silent", "works")
	var silentCanceled atomic.Bool
	started := time.Now()
	way, err := downloader.Download(context.Background(), "lists.example", func(ctx context.Context, way string, _ *http.Client, progress func(int)) (any, error) {
		if way == "silent" {
			<-ctx.Done()
			silentCanceled.Store(true)
			return nil, ctx.Err()
		}
		progress(0)
		progress(100)
		return "list", nil
	}, accepting)
	require.NoError(t, err)
	require.Equal(t, "works", way)
	require.GreaterOrEqual(t, time.Since(started), testPlan.Wait)
	require.Eventually(t, silentCanceled.Load, time.Second, 5*time.Millisecond)
	ways, _ := downloader.Ways("lists.example")
	require.Equal(t, []string{"works", "silent"}, ways)
}

// While a body comes no other way starts, however long it takes: a second copy of a big list
// would be held at once.
func TestDownloaderBodyHoldsTheNext(t *testing.T) {
	downloader := testDownloader("slow-body", "other")
	var otherStarted atomic.Bool
	way, err := downloader.Download(context.Background(), "lists.example", func(ctx context.Context, way string, _ *http.Client, progress func(int)) (any, error) {
		if way == "other" {
			otherStarted.Store(true)
			return "list", nil
		}
		progress(0)
		for range 25 {
			// steady parts, closer than Body, for many Waits
			time.Sleep(testPlan.Body / 3)
			progress(10)
		}
		return "list", nil
	}, accepting)
	require.NoError(t, err)
	require.Equal(t, "slow-body", way)
	require.False(t, otherStarted.Load())
}

// A result accept refuses (a page of an ISP with status 200) fails its way and the next one is
// started at once. The refused way is the first of the list: it stays right after the way that
// brought the file.
func TestDownloaderAcceptRefuses(t *testing.T) {
	downloader := testDownloader("page", "works", "spare")
	started := time.Now()
	way, err := downloader.Download(context.Background(), "lists.example", func(ctx context.Context, way string, _ *http.Client, progress func(int)) (any, error) {
		progress(0)
		return way, nil
	}, func(way string, result any) error {
		if result == "page" {
			return errors.New("not a list")
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, "works", way)
	require.Less(t, time.Since(started), testPlan.Wait)
	ways, together := downloader.Ways("lists.example")
	require.Equal(t, []string{"works", "page", "spare"}, ways)
	require.False(t, together)
}

// At most Most ways at once, however many are silent.
func TestDownloaderMostAtOnce(t *testing.T) {
	downloader := testDownloader("a", "b", "c", "d", "e")
	var access sync.Mutex
	running, most := 0, 0
	ctx, cancel := context.WithTimeout(context.Background(), 8*testPlan.Wait)
	defer cancel()
	_, err := downloader.Download(ctx, "lists.example", func(ctx context.Context, way string, _ *http.Client, progress func(int)) (any, error) {
		access.Lock()
		running++
		most = max(most, running)
		access.Unlock()
		<-ctx.Done()
		access.Lock()
		running--
		access.Unlock()
		return nil, ctx.Err()
	}, accepting)
	require.Error(t, err)
	// a way started just before the deadline may still be counting itself in
	time.Sleep(testPlan.Wait)
	access.Lock()
	defer access.Unlock()
	require.Equal(t, testPlan.Most, most)
}

// When every way fails the error names each, and ways cut by the caller's deadline are not
// remembered as failed.
func TestDownloaderAllFail(t *testing.T) {
	downloader := testDownloader("a", "b")
	_, err := downloader.Download(context.Background(), "lists.example", func(ctx context.Context, way string, _ *http.Client, progress func(int)) (any, error) {
		return nil, errors.New(way + " refused")
	}, accepting)
	require.Error(t, err)
	for _, text := range []string{"a: a refused", "b: b refused"} {
		require.Contains(t, err.Error(), text)
	}
	cut := testDownloader("silent")
	ctx, cancel := context.WithTimeout(context.Background(), testPlan.Wait)
	defer cancel()
	_, err = cut.Download(ctx, "lists.example", func(ctx context.Context, way string, _ *http.Client, progress func(int)) (any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}, accepting)
	require.Error(t, err)
	_, together := cut.Ways("lists.example")
	require.False(t, together)
}

// The memory keeps memoryHosts hosts, the least recently used forgotten first.
func TestDownloadMemoryBound(t *testing.T) {
	memory := NewDownloadMemory()
	for index := range memoryHosts + 10 {
		memory.failed("host-"+strconv.Itoa(index), "direct")
	}
	require.LessOrEqual(t, len(memory.hosts), memoryHosts)
}

// A way forgotten (its tag names another outbound now) is not known for any host any more.
func TestDownloadMemoryForget(t *testing.T) {
	downloader := testDownloader("direct", "a", "b")
	downloader.Record("lists.example", "b", nil, time.Second, 10)
	downloader.Record("lists.example", "direct", errors.New("reset"), 0, 0)
	downloader.Record("other.example", "a", errors.New("reset"), 0, 0)
	downloader.memory.Forget("b")
	downloader.memory.Forget("a")
	ways, together := downloader.Ways("lists.example")
	require.Equal(t, []string{"direct", "a", "b"}, ways)
	require.True(t, together)
	ways, _ = downloader.Ways("other.example")
	require.Equal(t, []string{"direct", "a", "b"}, ways)
}

// testOutbounds are outbounds by tag: a group selects what its entry names.
type testOutbounds struct {
	adapter.OutboundManager
	selects map[string]string
}

type testOutbound struct {
	adapter.OutboundGroup
	tag      string
	selected adapter.Outbound
}

func (o *testOutbound) Tag() string { return o.tag }

func (o *testOutbound) Selected(string) adapter.Outbound { return o.selected }

type testLeaf struct {
	adapter.Outbound
	tag string
}

func (o *testLeaf) Tag() string { return o.tag }

func (m *testOutbounds) Outbound(tag string) (adapter.Outbound, bool) {
	if selected, isGroup := m.selects[tag]; isGroup {
		next, _ := m.Outbound(selected)
		return &testOutbound{tag: tag, selected: next}, true
	}
	return &testLeaf{tag: tag}, true
}

// The outbounds the program excludes are no ways, nor is a group while it uses one of them (a
// rule fallen back to its last reserve); excluding nothing again gives them back.
func TestDownloaderExcluded(t *testing.T) {
	downloader := testDownloader("direct", "rule-a", "rule-b", "helper")
	outbounds := &testOutbounds{selects: map[string]string{"rule-a": "rule-a-test", "rule-a-test": "reserve", "rule-b": "nl"}}
	downloader.Outbounds = outbounds
	downloader.memory.SetExcluded([]string{"reserve", "helper"})
	ways, _ := downloader.Ways("lists.example")
	require.Equal(t, []string{"direct", "rule-b"}, ways)
	outbounds.selects["rule-a-test"] = "fi"
	ways, _ = downloader.Ways("lists.example")
	require.Equal(t, []string{"direct", "rule-a", "rule-b"}, ways)
	downloader.memory.SetExcluded(nil)
	ways, _ = downloader.Ways("lists.example")
	require.Equal(t, []string{"direct", "rule-a", "rule-b", "helper"}, ways)
}

// A body that pauses longer than Body has the next way started beside it while it is small; once
// Large bytes of it came, only a pause longer than LargeBody does.
func TestDownloaderLargeBodyWaitsLonger(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		before    int
		nextStart bool
	}{
		{"small", 100, true},
		{"large", 2000, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			downloader := testDownloader("pausing", "other")
			var otherStarted atomic.Bool
			_, err := downloader.Download(context.Background(), "lists.example", func(ctx context.Context, way string, _ *http.Client, progress func(int)) (any, error) {
				if way == "other" {
					otherStarted.Store(true)
					<-ctx.Done()
					return nil, ctx.Err()
				}
				progress(0)
				progress(testCase.before)
				// a pause of 6 Body (180 ms), shorter than LargeBody (300 ms): after its first Body
				// there are 150 ms left, more than the 100 ms between two looks of the download
				time.Sleep(6 * testPlan.Body)
				progress(10)
				return "list", nil
			}, accepting)
			require.NoError(t, err)
			require.Equal(t, testCase.nextStart, otherStarted.Load())
		})
	}
}

// countingTransport counts the closes of its idle connections.
type countingTransport struct{ closes atomic.Int32 }

func (t *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("no network in the test")
}

func (t *countingTransport) CloseIdleConnections() { t.closes.Add(1) }

func (t *countingTransport) Reset() {}

// A caller that closes the idle connections of its client after a download (a rule set after its
// update) closes those of the way only when no other download, nor a hold, uses it: the downloads
// through one way share its pooled connections, as the users of a shared client do.
func TestDownloaderSharesTheConnectionsOfAWay(t *testing.T) {
	transport := &countingTransport{}
	downloader := NewDownloader(log.NewNOPFactory().Logger(), []string{"direct"}, map[string]adapter.HTTPTransport{"direct": transport}, nil, nil)
	downloader.Plan = testPlan
	closing := func(result string) adapter.HTTPDownloadTry {
		return func(_ context.Context, _ string, client *http.Client, _ func(int)) (any, error) {
			client.CloseIdleConnections()
			return result, nil
		}
	}
	started, release := make(chan struct{}), make(chan struct{})
	var firstErr error
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		_, firstErr = downloader.Download(context.Background(), "a.example", func(ctx context.Context, way string, client *http.Client, progress func(int)) (any, error) {
			close(started)
			<-release
			return closing("a")(ctx, way, client, progress)
		}, accepting)
	}()
	<-started
	_, err := downloader.Download(context.Background(), "b.example", closing("b"), accepting)
	require.NoError(t, err)
	require.Zero(t, transport.closes.Load(), "the first download still uses the way")
	close(release)
	wait.Wait()
	require.NoError(t, firstErr)
	require.Equal(t, int32(1), transport.closes.Load(), "closed when the last one is done")

	hold := downloader.Hold()
	_, err = downloader.Download(context.Background(), "a.example", closing("a"), accepting)
	require.NoError(t, err)
	require.Equal(t, int32(1), transport.closes.Load(), "kept while held")
	hold.CloseIdleConnections()
	hold.CloseIdleConnections()
	require.Equal(t, int32(2), transport.closes.Load(), "closed once the hold is released, once")
}

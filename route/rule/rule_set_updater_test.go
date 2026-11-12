package rule

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

// An update asked for now takes every remote rule-set, due or not, and tells how many
// got a new list and how many failed; a scheduled update is not made earlier by it.
func TestRuleSetUpdaterUpdateNow(t *testing.T) {
	var served atomic.Int32
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served.Add(1)
		io.WriteString(w, testSourceSet)
	}))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer bad.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sets := make([]adapter.RuleSet, 2)
	for index, url := range []string{good.URL, bad.URL} {
		set := newTestRuleSet(url)
		set.ctx = ctx
		set.options.Format = C.RuleSetFormatSource
		// downloaded a moment ago: not due for an hour
		set.updateInterval = time.Hour
		set.lastUpdated = time.Now()
		sets[index] = set
	}
	updater := NewRuleSetUpdater(ctx, sets)
	updater.Start()

	time.Sleep(100 * time.Millisecond)
	require.Zero(t, served.Load(), "a rule-set that is not due was updated by the schedule")
	for round := int32(1); round <= 2; round++ {
		summary, err := updater.UpdateNow(ctx)
		require.NoError(t, err)
		require.Equal(t, RuleSetUpdateSummary{Total: 2, Loaded: 1, Failed: 1}, summary)
		require.Equal(t, round, served.Load())
	}
	time.Sleep(100 * time.Millisecond)
	require.EqualValues(t, 2, served.Load(), "the update asked for was followed by one more")

	// one that waits is let go when the caller gives up, and when the updater is closed
	short, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stop()
	require.NoError(t, updater.Close())
	_, err := updater.UpdateNow(short)
	require.Error(t, err)
}

// With no remote rule-set there is no updater, and nothing to wait for.
func TestRuleSetUpdaterWithoutRemoteRuleSets(t *testing.T) {
	require.Nil(t, NewRuleSetUpdater(context.Background(), nil))
}

// Rule-sets due together are downloaded together, ruleSetUpdateConcurrency at a time: six
// sets whose server answers after 300 ms take two rounds, not six.
func TestRuleSetUpdaterConcurrent(t *testing.T) {
	var inFlight, most atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			seen := most.Load()
			if now <= seen || most.CompareAndSwap(seen, now) {
				break
			}
		}
		time.Sleep(300 * time.Millisecond)
		io.WriteString(w, testSourceSet)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sets := make([]adapter.RuleSet, 6)
	for index := range sets {
		set := newTestRuleSet(server.URL)
		set.ctx = ctx
		set.options.Format = C.RuleSetFormatSource
		set.updateInterval = time.Hour
		set.lastUpdated = time.Now()
		sets[index] = set
	}
	updater := NewRuleSetUpdater(ctx, sets)
	updater.Start()
	defer updater.Close()
	started := time.Now()
	summary, err := updater.UpdateNow(ctx)
	require.NoError(t, err)
	require.Equal(t, RuleSetUpdateSummary{Total: 6, Loaded: 6}, summary)
	require.EqualValues(t, ruleSetUpdateConcurrency, most.Load())
	require.Less(t, time.Since(started), 1500*time.Millisecond, "the sets were downloaded one by one")
}

// Big lists are updated one at a time, small ones together as before: two sets that hold a
// big list each never download at once, while the three small ones do.
func TestRuleSetUpdaterBigOneAtATime(t *testing.T) {
	var bigInFlight, bigMost, smallInFlight, smallMost atomic.Int32
	raise := func(most *atomic.Int32, now int32) {
		for {
			seen := most.Load()
			if now <= seen || most.CompareAndSwap(seen, now) {
				return
			}
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inFlight, most := &smallInFlight, &smallMost
		if r.URL.Path == "/big" {
			inFlight, most = &bigInFlight, &bigMost
		}
		raise(most, inFlight.Add(1))
		defer inFlight.Add(-1)
		time.Sleep(200 * time.Millisecond)
		io.WriteString(w, testSourceSet)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sets []adapter.RuleSet
	for index := range 5 {
		path := "/small"
		if index%2 == 0 && index < 4 {
			path = "/big"
		}
		set := newTestRuleSet(server.URL + path)
		set.ctx = ctx
		set.options.Format = C.RuleSetFormatSource
		set.updateInterval = time.Hour
		set.lastUpdated = time.Now()
		if path == "/big" {
			set.contentSize.Store(heavyRuleSetSize)
		}
		sets = append(sets, set)
	}
	updater := NewRuleSetUpdater(ctx, sets)
	updater.Start()
	defer updater.Close()
	summary, err := updater.UpdateNow(ctx)
	require.NoError(t, err)
	require.Equal(t, RuleSetUpdateSummary{Total: 5, Loaded: 5}, summary)
	require.EqualValues(t, 1, bigMost.Load(), "two big lists were downloaded at once")
	require.EqualValues(t, 3, smallMost.Load())
	// what was loaded tells its size: the small list of the test is small
	require.Less(t, sets[0].(*RemoteRuleSet).contentSize.Load(), int64(heavyRuleSetSize))
}

package rule

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

// With SING_BOX_RULE_SET_START_EMPTY a set that has nothing cached does not download at
// the start: it starts empty, its content unknown to the DNS router, and the updater
// fetches it. Without it, the start downloads it.
func TestRemoteRuleSetStartEmpty(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write([]byte(`{"version":3,"rules":[{"domain_suffix":["example.com"]}]}`))
	}))
	defer server.Close()
	defer func(saved func() bool) { ruleSetStartEmpty = saved }(ruleSetStartEmpty)

	ruleSetStartEmpty = func() bool { return true }
	set := newTestRuleSet(server.URL)
	set.ctx = context.Background()
	set.options.Format = C.RuleSetFormatSource
	set.startWithNothingLoaded(context.Background())
	require.Zero(t, requests.Load(), "the start downloaded the set")
	require.True(t, set.startedEmpty)
	require.True(t, set.Metadata().ContainsIPCIDRRule && set.Metadata().ContainsNonIPCIDRRule, "an empty set's content is unknown: mixed")

	ruleSetStartEmpty = func() bool { return false }
	set = newTestRuleSet(server.URL)
	set.ctx = context.Background()
	set.options.Format = C.RuleSetFormatSource
	set.startWithNothingLoaded(context.Background())
	require.Equal(t, int32(1), requests.Load())
	require.False(t, set.startedEmpty)
}

// savingCache is a cache file that keeps the rule sets it is given; nothing else of it is used.
type savingCache struct {
	adapter.CacheFile
	saved map[string]*adapter.SavedBinary
}

func (c *savingCache) LoadRuleSet(tag string) *adapter.SavedBinary { return c.saved[tag] }

func (c *savingCache) SaveRuleSet(tag string, set *adapter.SavedBinary) error {
	c.saved[tag] = set
	return nil
}

// A callback is run after a download has saved the content to the cache file: a callback
// that reads the set from there gets the new content, not the previous one.
func TestRemoteRuleSetCallbackAfterCache(t *testing.T) {
	content := []byte(`{"version":3,"rules":[{"ip_cidr":["192.0.2.0/24"]}]}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(content)
	}))
	defer server.Close()
	set := newTestRuleSet(server.URL)
	set.ctx = context.Background()
	set.options.Format = C.RuleSetFormatSource
	cache := &savingCache{saved: make(map[string]*adapter.SavedBinary)}
	set.cacheFile = cache
	var seen []byte
	set.RegisterCallback(func(adapter.RuleSet) {
		if saved := cache.LoadRuleSet("test"); saved != nil {
			seen = saved.Content
		}
	})
	require.NoError(t, set.fetch(context.Background(), false))
	require.Equal(t, string(content), string(seen))
}

// A list written as text is downloaded and matched as any rule-set; a page served in its
// place is refused, and the rules it had stay.
func TestRemoteRuleSetText(t *testing.T) {
	var body atomic.Value
	body.Store("example.com\n10.0.0.0/8\n")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body.Load().(string)))
	}))
	defer server.Close()
	set := newTestRuleSet(server.URL)
	set.ctx = context.Background()
	set.options.Format = C.RuleSetFormatText
	require.NoError(t, set.fetch(context.Background(), false))
	require.True(t, set.Match(&adapter.InboundContext{Domain: "www.example.com"}))
	require.False(t, set.Match(&adapter.InboundContext{Domain: "example.org"}))
	body.Store("<html><body>\nAccess to this resource is blocked\n</body></html>\n")
	require.Error(t, set.fetch(context.Background(), false))
	require.True(t, set.Match(&adapter.InboundContext{Domain: "www.example.com"}))
}

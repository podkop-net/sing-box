package rule

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

// checkingCache is a cache file that keeps rule sets and the times they were found up to
// date, and counts the saves of rule sets; nothing else of it is used.
type checkingCache struct {
	adapter.CacheFile
	saved   map[string]*adapter.SavedBinary
	saves   int
	checked map[string]time.Time
}

func (c *checkingCache) LoadRuleSet(tag string) *adapter.SavedBinary { return c.saved[tag] }

func (c *checkingCache) SaveRuleSet(tag string, set *adapter.SavedBinary) error {
	c.saves++
	c.saved[tag] = set
	return nil
}

func (c *checkingCache) LoadRuleSetChecked(tag string) time.Time { return c.checked[tag] }

func (c *checkingCache) StoreRuleSetChecked(tag string, at time.Time) error {
	c.checked[tag] = at
	return nil
}

// An answer "not modified" keeps the time alone: the list is not written again.
func TestRemoteRuleSetNotModifiedKeepsTheTimeOnly(t *testing.T) {
	content := []byte(`{"version":3,"rules":[{"domain_suffix":["example.com"]}]}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Etag", `"v1"`)
		w.Write(content)
	}))
	defer server.Close()
	cache := &checkingCache{saved: make(map[string]*adapter.SavedBinary), checked: make(map[string]time.Time)}
	set := newTestRuleSet(server.URL)
	set.options.Format = C.RuleSetFormatSource
	set.cacheFile = cache
	require.NoError(t, set.fetch(context.Background(), nil))
	require.Equal(t, 1, cache.saves)
	downloaded := cache.saved["test"].LastUpdated

	time.Sleep(10 * time.Millisecond)
	require.NoError(t, set.fetch(context.Background(), nil))
	require.Equal(t, 1, cache.saves, "the list is not saved again")
	require.True(t, cache.checked["test"].After(downloaded))
}

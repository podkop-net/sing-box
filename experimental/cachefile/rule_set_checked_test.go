package cachefile

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// The time a rule set was found up to date is kept apart from its content, and stays
// across a reopen; a rule set without one has the zero time.
func TestRuleSetChecked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	cacheFile := openTestCacheFile(t, path)
	require.NoError(t, cacheFile.SaveRuleSet("lists", &adapter.SavedBinary{Content: []byte("list"), LastUpdated: time.Unix(100, 0)}))
	checked := time.Unix(200, 5)
	require.NoError(t, cacheFile.StoreRuleSetChecked("lists", checked))
	require.True(t, cacheFile.LoadRuleSetChecked("other").IsZero())
	require.NoError(t, cacheFile.Close())

	cacheFile = openTestCacheFile(t, path)
	defer cacheFile.Close()
	require.True(t, checked.Equal(cacheFile.LoadRuleSetChecked("lists")))
	saved := cacheFile.LoadRuleSet("lists")
	require.Equal(t, "list", string(saved.Content))
	require.True(t, time.Unix(100, 0).Equal(saved.LastUpdated), "the content is not written again")
}

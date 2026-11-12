package cachefile

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// The block detector's outcome stays across a reopen: the start of the cache file deletes the
// buckets it does not know.
func TestDetectOutcome(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	cacheFile := openTestCacheFile(t, path)
	at := time.Unix(1000, 0)
	require.NoError(t, cacheFile.StoreDetectOutcome("key", adapter.DetectRefused|adapter.DetectFailed, "firefox", at))
	_, _, _, loaded := cacheFile.LoadDetectOutcome("other")
	require.False(t, loaded)
	require.NoError(t, cacheFile.Close())

	cacheFile = openTestCacheFile(t, path)
	defer cacheFile.Close()
	flags, fingerprint, stored, loaded := cacheFile.LoadDetectOutcome("key")
	require.True(t, loaded)
	require.Equal(t, adapter.DetectRefused|adapter.DetectFailed, flags)
	require.Equal(t, "firefox", fingerprint)
	require.True(t, at.Equal(stored))
}

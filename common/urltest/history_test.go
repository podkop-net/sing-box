package urltest

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// A failure takes the result away and is kept until a test passes; forgetting a tag is no failure
// and leaves nothing of it.
func TestHistoryStorageFailure(t *testing.T) {
	storage := NewHistoryStorage()
	at := time.Unix(100, 0)
	storage.StoreURLTestHistory("s", &adapter.URLTestHistory{Time: at, Delay: 10})
	_, loaded := storage.LoadURLTestFailure("s")
	require.False(t, loaded)

	storage.StoreURLTestFailure("s", at)
	require.Nil(t, storage.LoadURLTestHistory("s"))
	failed, loaded := storage.LoadURLTestFailure("s")
	require.True(t, loaded)
	require.True(t, at.Equal(failed))

	storage.StoreURLTestHistory("s", &adapter.URLTestHistory{Time: at, Delay: 10})
	_, loaded = storage.LoadURLTestFailure("s")
	require.False(t, loaded)

	storage.DeleteURLTestHistory("s")
	require.Nil(t, storage.LoadURLTestHistory("s"))
	_, loaded = storage.LoadURLTestFailure("s")
	require.False(t, loaded, "forgetting a tag recorded a failure")

	storage.StoreURLTestFailure("s", at)
	storage.StoreDownloadResult("s", DownloadResult{At: at, Received: 16 << 10, Stopped: true})
	storage.DeleteURLTestHistory("s")
	_, loaded = storage.LoadURLTestFailure("s")
	require.False(t, loaded, "the failure of what the tag was before")
	_, loaded = storage.LoadDownloadResult("s")
	require.False(t, loaded, "the download of what the tag was before")
}

// A passed URL test says nothing of a download; a failed one neither.
func TestHistoryStorageDownload(t *testing.T) {
	storage := NewHistoryStorage()
	_, loaded := storage.LoadDownloadResult("s")
	require.False(t, loaded)
	result := DownloadResult{At: time.Unix(100, 0), Received: 16 << 10, Stopped: true}
	storage.StoreDownloadResult("s", result)
	storage.StoreURLTestHistory("s", &adapter.URLTestHistory{Delay: 10})
	storage.StoreURLTestFailure("s", time.Unix(200, 0))
	found, loaded := storage.LoadDownloadResult("s")
	require.True(t, loaded)
	require.Equal(t, result, found)

	var none *HistoryStorage
	_, loaded = none.LoadURLTestFailure("s")
	require.False(t, loaded)
	_, loaded = none.LoadDownloadResult("s")
	require.False(t, loaded)
}

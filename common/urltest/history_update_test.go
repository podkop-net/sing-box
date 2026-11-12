package urltest

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// A round stored at once (UpdateURLTestHistory, the URL test of upstream's group, which the daemon
// runs for a selector) keeps what the history knows of a tag beyond its delay as one result at a
// time does: a stored tag has passed, a deleted one is forgotten.
func TestHistoryStorageUpdate(t *testing.T) {
	storage := NewHistoryStorage()
	at := time.Unix(100, 0)
	storage.StoreURLTestFailure("passed", at)
	storage.StoreURLTestHistory("deleted", &adapter.URLTestHistory{Time: at, Delay: 10})
	storage.StoreURLTestSample("deleted", 1, 3, 10)
	storage.StoreURLTestLinkResult("deleted", "https://example.com/", true)
	storage.StoreURLTestFailure("failed", at)
	storage.UpdateURLTestHistory(map[string]*adapter.URLTestHistory{"passed": {Time: at, Delay: 20}}, []string{"deleted"})

	require.Equal(t, uint16(20), storage.LoadURLTestHistory("passed").Delay)
	_, loaded := storage.LoadURLTestFailure("passed")
	require.False(t, loaded, "a failure of a tag stored since")

	require.Nil(t, storage.LoadURLTestHistory("deleted"))
	require.Empty(t, storage.LoadURLTestSamples("deleted"), "the delays of a tag deleted since")
	_, known := storage.URLTestLinkAnswered("deleted", "https://example.com/")
	require.False(t, known, "the URLs of a tag deleted since")

	_, loaded = storage.LoadURLTestFailure("failed")
	require.True(t, loaded, "a tag the update does not name")
}

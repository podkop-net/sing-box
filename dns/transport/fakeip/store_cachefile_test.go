package fakeip

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// startWithCacheFile starts a store on a real cache file, as sing-box does.
func startWithCacheFile(t *testing.T, path string) (*Store, *cachefile.CacheFile) {
	t.Helper()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	cacheFile := cachefile.New(ctx, option.CacheFileOptions{Enabled: true, Path: path, StoreFakeIP: true})
	require.NoError(t, cacheFile.Start(adapter.StartStateInitialize))
	service.MustRegister[adapter.CacheFile](ctx, cacheFile)
	store := NewStore(ctx, logger.NOP(), netip.MustParsePrefix("198.18.0.0/15"), netip.Prefix{})
	store.manual = true
	require.NoError(t, store.Start())
	require.NotNil(t, store.storage, "the cache file keeps the table")
	return store, cacheFile
}

// killed copies the cache file as a killed process leaves it: no write is under way.
func killed(t *testing.T, store *Store, path string) string {
	t.Helper()
	store.saveAccess.Lock()
	defer store.saveAccess.Unlock()
	source, err := os.Open(path)
	require.NoError(t, err)
	defer source.Close()
	copyPath := filepath.Join(t.TempDir(), "cache.db")
	target, err := os.Create(copyPath)
	require.NoError(t, err)
	_, err = io.Copy(target, source)
	require.NoError(t, err)
	require.NoError(t, target.Close())
	return copyPath
}

func TestStoreOnCacheFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "cache.db")
	store, cacheFile := startWithCacheFile(t, path)
	given := make(map[string]netip.Addr)
	for i := range 100 {
		domain := fmt.Sprint("saved-", i, ".test")
		given[domain] = mustCreate(t, store, domain)
	}
	require.NoError(t, store.save(saveRequest{}))
	lost := make(map[string]netip.Addr)
	for i := range 100 {
		domain := fmt.Sprint("lost-", i, ".test")
		lost[domain] = mustCreate(t, store, domain)
	}

	// kill -9 with 100 addresses given out and not saved
	killedStore, killedFile := startWithCacheFile(t, killed(t, store, path))
	for domain, old := range given {
		loadedDomain, loaded := killedStore.Lookup(old)
		require.True(t, loaded)
		require.Equal(t, domain, loadedDomain)
		require.Equal(t, old, mustCreate(t, killedStore, domain))
	}
	taken := make(map[netip.Addr]bool)
	for _, old := range lost {
		_, loaded := killedStore.Lookup(old)
		require.False(t, loaded, "no record: the connection is refused")
		taken[old] = true
	}
	for i := range 2000 {
		next := mustCreate(t, killedStore, fmt.Sprint("new-", i, ".test"))
		require.False(t, taken[next], "an address a client may hold is not given to another domain")
	}
	require.NoError(t, killedStore.Close())
	require.NoError(t, killedFile.Close())

	// a clean stop: nothing is lost, nothing is stepped over
	require.NoError(t, store.Close())
	require.NoError(t, cacheFile.Close())
	store, cacheFile = startWithCacheFile(t, path)
	for domain, old := range given {
		require.Equal(t, old, mustCreate(t, store, domain))
	}
	for domain, old := range lost {
		require.Equal(t, old, mustCreate(t, store, domain))
	}
	require.Equal(t, netip.MustParseAddr("198.18.0.202"), mustCreate(t, store, "next.test"))

	// a version that keeps the map on disk opens the file: addresses lead to their
	// domains, the position is where it stopped
	require.NoError(t, store.Close())
	domain, loaded := cacheFile.FakeIPLoad(given["saved-0.test"])
	require.True(t, loaded)
	require.Equal(t, "saved-0.test", domain)
	metadata := cacheFile.FakeIPMetadata()
	require.NotNil(t, metadata)
	require.Equal(t, netip.MustParseAddr("198.18.0.202"), metadata.Inet4Current)
	require.NoError(t, cacheFile.Close())
}

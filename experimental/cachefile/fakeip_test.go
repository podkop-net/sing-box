package cachefile

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// testCacheFile is a cache file with the scope it was started with: closing the scope
// closes the file, as when sing-box stops.
type testCacheFile struct {
	*CacheFile
	scope *adapter.Scope
}

func (f *testCacheFile) Close() error {
	return f.scope.Close()
}

func openTestCacheFile(t *testing.T, path string) *testCacheFile {
	t.Helper()
	cacheFile := New(context.Background(), logger.NOP(), option.CacheFileOptions{Enabled: true, Path: path, StoreFakeIP: true})
	scope := adapter.NewScope(context.Background(), logger.NOP())
	require.NoError(t, cacheFile.Start(adapter.StartStateInitialize, scope))
	return &testCacheFile{cacheFile, scope}
}

func loadTable(t *testing.T, cacheFile *testCacheFile, refuse ...netip.Addr) (map[netip.Addr]string, *adapter.FakeIPMetadata, bool) {
	t.Helper()
	table := make(map[netip.Addr]string)
	metadata, clean, err := cacheFile.FakeIPLoadTable(func(address netip.Addr, domain string) bool {
		for _, refused := range refuse {
			if refused == address {
				return false
			}
		}
		table[address] = domain
		return true
	})
	require.NoError(t, err)
	return table, metadata, clean
}

func TestFakeIPTable(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "cache.db")
	cacheFile := openTestCacheFile(t, path)
	inet4Range := netip.MustParsePrefix("198.18.0.0/15")
	inet6Range := netip.MustParsePrefix("fc00::/18")
	first, second, third := netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("198.18.0.3"), netip.MustParseAddr("fc00::2")

	table, metadata, clean := loadTable(t, cacheFile)
	require.Empty(t, table)
	require.Nil(t, metadata)
	require.False(t, clean)

	position := &adapter.FakeIPMetadata{Inet4Range: inet4Range, Inet6Range: inet6Range, Inet4Current: netip.MustParseAddr("198.18.4.1"), Inet6Current: netip.MustParseAddr("fc00::401")}
	require.NoError(t, cacheFile.FakeIPSaveChanges(map[netip.Addr]string{first: "a.test", second: "b.test", third: "a.test"}, nil, position, false))
	require.NoError(t, cacheFile.FakeIPSaveChanges(nil, []netip.Addr{second, netip.MustParseAddr("198.18.0.9")}, position, false))
	require.NoError(t, cacheFile.Close())

	// what a crash leaves: the records and the position saved ahead
	cacheFile = openTestCacheFile(t, path)
	table, metadata, clean = loadTable(t, cacheFile)
	require.Equal(t, map[netip.Addr]string{first: "a.test", third: "a.test"}, table)
	require.Equal(t, position, metadata)
	require.False(t, clean)
	// a version that keeps the map on disk reads the addresses, and no position
	domain, loaded := cacheFile.FakeIPLoad(first)
	require.True(t, loaded)
	require.Equal(t, "a.test", domain)
	require.Nil(t, cacheFile.FakeIPMetadata())

	// a clean stop: the exact position, also where older versions read it
	exact := &adapter.FakeIPMetadata{Inet4Range: inet4Range, Inet6Range: inet6Range, Inet4Current: first, Inet6Current: third}
	require.NoError(t, cacheFile.FakeIPSaveChanges(nil, nil, exact, true))
	require.NoError(t, cacheFile.Close())
	cacheFile = openTestCacheFile(t, path)
	require.Equal(t, exact, cacheFile.FakeIPMetadata(), "an older version finds the position")

	// an older version ran: it gave out an address, wrote its index of domains and
	// stopped cleanly at a position this version did not save
	require.NoError(t, cacheFile.FakeIPStore(second, "c.test"))
	later := &adapter.FakeIPMetadata{Inet4Range: inet4Range, Inet6Range: inet6Range, Inet4Current: second, Inet6Current: third}
	require.NoError(t, cacheFile.FakeIPSaveMetadata(later))
	require.NoError(t, cacheFile.Close())

	cacheFile = openTestCacheFile(t, path)
	table, metadata, clean = loadTable(t, cacheFile, third)
	require.Equal(t, map[netip.Addr]string{first: "a.test", second: "c.test"}, table)
	require.Equal(t, later, metadata, "the position of the clean stop is the newer one")
	require.True(t, clean)
	require.NoError(t, cacheFile.view(func(tx *bbolt.Tx) error {
		require.Nil(t, tx.Bucket(bucketFakeIPDomain4), "the index of domains is not kept")
		require.Nil(t, tx.Bucket(bucketFakeIPDomain6))
		require.Nil(t, tx.Bucket(bucketFakeIP).Get(keyMetadata), "valid only until an address is given out")
		require.Nil(t, tx.Bucket(bucketFakeIP).Get(third.AsSlice()), "a refused record is removed")
		return nil
	}))
	// without a clean stop the position saved ahead is what is left
	table, metadata, clean = loadTable(t, cacheFile)
	require.Len(t, table, 2)
	require.Equal(t, exact, metadata)
	require.False(t, clean)

	// a clean stop, then addresses are given out again: the position of the clean stop
	// must not outlive that
	require.NoError(t, cacheFile.FakeIPSaveChanges(nil, nil, later, true))
	require.NoError(t, cacheFile.FakeIPSaveChanges(map[netip.Addr]string{third: "d.test"}, nil, position, false))
	require.Nil(t, cacheFile.FakeIPMetadata())
	_, metadata, clean = loadTable(t, cacheFile)
	require.Equal(t, position, metadata)
	require.False(t, clean)
	require.NoError(t, cacheFile.Close())
}

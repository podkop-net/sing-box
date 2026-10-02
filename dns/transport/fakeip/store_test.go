package fakeip

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// fakeStorage is a table storage in memory: what is in it is what a crash leaves.
type fakeStorage struct {
	access      sync.Mutex
	table       map[netip.Addr]string
	cursor      *adapter.FakeIPMetadata // the position saved ahead
	cleanKey    *adapter.FakeIPMetadata // the position saved on a clean stop
	domainIndex bool                    // the buckets of versions that kept the map on disk
	generation  uint64
	fail        bool  // saves fail
	loadError   error // the table is read, the change of the file that follows fails
	resetError  error
	saves       int
	onSave      func() // runs while a save is on its way to the storage
}

func newFakeStorage() *fakeStorage {
	return &fakeStorage{table: make(map[netip.Addr]string)}
}

func copyMetadata(metadata *adapter.FakeIPMetadata) *adapter.FakeIPMetadata {
	if metadata == nil {
		return nil
	}
	saved := *metadata
	return &saved
}

// crash returns the storage as a process started after a kill finds it.
func (f *fakeStorage) crash() *fakeStorage {
	f.access.Lock()
	defer f.access.Unlock()
	left := newFakeStorage()
	for address, domain := range f.table {
		left.table[address] = domain
	}
	left.cursor = copyMetadata(f.cursor)
	left.cleanKey = copyMetadata(f.cleanKey)
	left.generation = f.generation
	return left
}

func (f *fakeStorage) FakeIPLoadTable(load func(address netip.Addr, domain string) bool) (*adapter.FakeIPMetadata, bool, error) {
	f.access.Lock()
	defer f.access.Unlock()
	metadata, clean := f.cleanKey, f.cleanKey != nil
	if !clean {
		metadata = f.cursor
	}
	var refused []netip.Addr
	for address, domain := range f.table {
		if !load(address, domain) {
			refused = append(refused, address)
		}
	}
	if f.loadError != nil {
		return copyMetadata(metadata), clean, f.loadError
	}
	f.cleanKey = nil
	f.domainIndex = false
	for _, address := range refused {
		delete(f.table, address)
	}
	return copyMetadata(metadata), clean, nil
}

func (f *fakeStorage) FakeIPSaveChanges(puts map[netip.Addr]string, deletes []netip.Addr, metadata *adapter.FakeIPMetadata, clean bool) error {
	if f.onSave != nil {
		f.onSave()
	}
	f.access.Lock()
	defer f.access.Unlock()
	if f.fail {
		return errors.New("no space left on device")
	}
	for _, address := range deletes {
		delete(f.table, address)
	}
	for address, domain := range puts {
		f.table[address] = domain
	}
	f.cursor = copyMetadata(metadata)
	f.cleanKey = nil
	if clean {
		f.cleanKey = copyMetadata(metadata)
	}
	f.saves++
	return nil
}

func (f *fakeStorage) FakeIPGeneration() uint64 {
	f.access.Lock()
	defer f.access.Unlock()
	return f.generation
}

func (f *fakeStorage) FakeIPReset() error {
	f.access.Lock()
	defer f.access.Unlock()
	if f.resetError != nil {
		return f.resetError
	}
	clear(f.table)
	return nil
}

func (f *fakeStorage) domainOf(address netip.Addr) string {
	f.access.Lock()
	defer f.access.Unlock()
	return f.table[address]
}

func (f *fakeStorage) records() int {
	f.access.Lock()
	defer f.access.Unlock()
	return len(f.table)
}

const (
	testIdle    = 1000 // ticks
	testProtect = 100
)

// newTestStore returns a started store whose clock, sweeps and saves the test drives.
func newTestStore(t *testing.T, storage *fakeStorage, inet4Range string, inet6Range string) *Store {
	t.Helper()
	store, err := startTestStore(storage, inet4Range, inet6Range)
	require.NoError(t, err)
	return store
}

func startTestStore(storage *fakeStorage, inet4Range string, inet6Range string) (*Store, error) {
	var prefix4, prefix6 netip.Prefix
	if inet4Range != "" {
		prefix4 = netip.MustParsePrefix(inet4Range)
	}
	if inet6Range != "" {
		prefix6 = netip.MustParsePrefix(inet6Range)
	}
	store := NewStore(context.Background(), logger.NOP(), prefix4, prefix6)
	store.manual = true
	store.idleTicks = testIdle
	store.protectTicks = testProtect
	store.startTick = testIdle + 2
	store.tick.Store(store.startTick)
	if storage != nil {
		store.testStorage = storage
	}
	return store, store.Start()
}

func (s *Store) advance(ticks uint32) {
	s.tick.Add(ticks)
}

// domainAt reads a record without using it.
func (s *Store) domainAt(address netip.Addr) string {
	if r := s.recordAt(address); r != nil {
		return r.domain
	}
	return ""
}

func (s *Store) recordAt(address netip.Addr) *record {
	p := s.poolOf(address)
	offset, _ := p.offset(address)
	return p.byOffset[offset]
}

func mustCreate(t *testing.T, store *Store, domain string) netip.Addr {
	t.Helper()
	address, err := store.Create(domain, false)
	require.NoError(t, err)
	return address
}

func address(text string) netip.Addr {
	return netip.MustParseAddr(text)
}

func TestCreateAndLookup(t *testing.T) {
	t.Parallel()
	for _, storage := range []*fakeStorage{nil, newFakeStorage()} {
		store := newTestStore(t, storage, "198.18.0.0/15", "fc00::/18")
		first := mustCreate(t, store, "example.com")
		require.Equal(t, address("198.18.0.2"), first, "the first address stays the one older versions gave")
		require.Equal(t, first, mustCreate(t, store, "example.com"))
		require.Equal(t, first, mustCreate(t, store, "Example.COM"), "one record for all spellings")
		second := mustCreate(t, store, "example.org")
		require.Equal(t, address("198.18.0.3"), second)

		first6, err := store.Create("example.com", true)
		require.NoError(t, err)
		require.Equal(t, address("fc00::2"), first6)

		domain, loaded := store.Lookup(first)
		require.True(t, loaded)
		require.Equal(t, "example.com", domain)
		domain, loaded = store.Lookup(first6)
		require.True(t, loaded)
		require.Equal(t, "example.com", domain)
		_, loaded = store.Lookup(address("198.18.0.4"))
		require.False(t, loaded)
		_, loaded = store.Lookup(address("198.18.0.0"))
		require.False(t, loaded)
		_, loaded = store.Lookup(address("10.0.0.1"))
		require.False(t, loaded)

		require.True(t, store.Contains(address("198.19.255.255")))
		require.False(t, store.Contains(address("198.20.0.0")))
		require.NoError(t, store.Close())
		_, err = store.Create("after.close", false)
		require.Error(t, err)
		_, loaded = store.Lookup(first)
		require.True(t, loaded, "lookups work after Close: connections may still arrive")
	}
}

func TestMissingRange(t *testing.T) {
	t.Parallel()
	store := newTestStore(t, nil, "198.18.0.0/15", "")
	_, err := store.Create("example.com", true)
	require.Error(t, err)
	_, loaded := store.Lookup(address("fc00::2"))
	require.False(t, loaded)
}

func TestRangeWithoutAddresses(t *testing.T) {
	t.Parallel()
	for _, prefix := range []string{"198.18.0.0/31", "198.18.0.0/32"} {
		_, err := startTestStore(nil, prefix, "")
		require.Error(t, err, prefix)
	}
	// a /30 has one address to give out: .2
	store := newTestStore(t, nil, "198.18.0.0/30", "")
	require.Equal(t, address("198.18.0.2"), mustCreate(t, store, "a"))
	require.Equal(t, address("198.18.0.2"), mustCreate(t, store, "b"), "the only address is taken from the domain unused longest")
	_, err := startTestStore(nil, "", "fc00::/127")
	require.Error(t, err)
}

func TestCleanRestart(t *testing.T) {
	t.Parallel()
	storage := newFakeStorage()
	store := newTestStore(t, storage, "198.18.0.0/15", "")
	given := make(map[string]netip.Addr)
	for i := range 50 {
		domain := fmt.Sprint("name-", i, ".test")
		given[domain] = mustCreate(t, store, domain)
	}
	require.NoError(t, store.Close())
	require.Equal(t, 50, storage.records())
	require.NotNil(t, storage.cleanKey, "the position is written where older versions read it")
	require.Equal(t, address("198.18.0.51"), storage.cleanKey.Inet4Current)

	store = newTestStore(t, storage, "198.18.0.0/15", "")
	require.Nil(t, storage.cleanKey, "valid only until this process gives out an address")
	for domain, old := range given {
		require.Equal(t, old, mustCreate(t, store, domain))
		loadedDomain, loaded := store.Lookup(old)
		require.True(t, loaded)
		require.Equal(t, domain, loadedDomain)
	}
	require.Equal(t, address("198.18.0.52"), mustCreate(t, store, "next.test"), "nothing is stepped over after a clean stop")
}

func TestCrashStepsOverTheReserve(t *testing.T) {
	t.Parallel()
	storage := newFakeStorage()
	store := newTestStore(t, storage, "198.18.0.0/15", "")
	saved := mustCreate(t, store, "saved.test")
	require.NoError(t, store.save(saveRequest{}))
	lost := mustCreate(t, store, "lost.test") // answered, not saved yet

	store = newTestStore(t, storage.crash(), "198.18.0.0/15", "")
	domain, loaded := store.Lookup(saved)
	require.True(t, loaded)
	require.Equal(t, "saved.test", domain)
	_, loaded = store.Lookup(lost)
	require.False(t, loaded, "an address that was not saved has no record: the connection is refused")
	for i := range 3000 {
		next := mustCreate(t, store, fmt.Sprint("new-", i, ".test"))
		require.NotEqual(t, lost, next, "it is not given to another domain")
		require.NotEqual(t, saved, next)
	}
	require.Equal(t, saved, mustCreate(t, store, "saved.test"))
}

func TestReserveIsExtendedBeforeItIsUsedUp(t *testing.T) {
	t.Parallel()
	storage := newFakeStorage()
	store := newTestStore(t, storage, "198.18.0.0/15", "")
	seen := make(map[netip.Addr]bool)
	// no background save: every reserve is saved by the query that needs it
	for i := range 3 * reserveStep {
		next := mustCreate(t, store, fmt.Sprint("a-", i, ".test"))
		require.False(t, seen[next])
		seen[next] = true
		// the saved position is never behind an address given out
		last := storage.cursor.Inet4Current
		require.False(t, last.Less(next), "position ", last, " is behind ", next)
	}
	// a crash at any point: nothing given out so far is given out again
	store = newTestStore(t, storage.crash(), "198.18.0.0/15", "")
	for i := range 3 * reserveStep {
		next := mustCreate(t, store, fmt.Sprint("b-", i, ".test"))
		require.False(t, seen[next], next)
	}
}

func TestStorageFailure(t *testing.T) {
	t.Parallel()
	storage := newFakeStorage()
	store := newTestStore(t, storage, "198.18.0.0/15", "")
	known := mustCreate(t, store, "known.test")
	storage.fail = true
	// known domains keep answering, new ones while the saved reserve lasts
	require.Equal(t, known, mustCreate(t, store, "known.test"))
	var given int
	for {
		_, err := store.Create(fmt.Sprint("new-", given, ".test"), false)
		if err != nil {
			break
		}
		given++
		require.Less(t, given, reserveStep+1, "nothing is given out past the saved reserve")
	}
	require.Greater(t, given, 0)
	require.Error(t, store.save(saveRequest{}))
	require.Equal(t, 0, storage.records())
	storage.fail = false
	mustCreate(t, store, "after.test")
	require.NoError(t, store.save(saveRequest{}))
	require.Equal(t, given+2, storage.records(), "what was given out during the failure is saved once the storage works")
}

func TestUnusedRecordsAreRemoved(t *testing.T) {
	t.Parallel()
	for _, storage := range []*fakeStorage{nil, newFakeStorage()} {
		store := newTestStore(t, storage, "198.18.0.0/15", "")
		queried := mustCreate(t, store, "queried.test")
		connected := mustCreate(t, store, "connected.test")
		idle := mustCreate(t, store, "idle.test")
		require.NoError(t, store.save(saveRequest{}))

		store.advance(testIdle - 1)
		mustCreate(t, store, "queried.test") // a query
		store.Lookup(connected)              // a new connection
		store.advance(1)
		store.sweep()
		// with a storage the record stays until its removal is saved
		if storage != nil {
			_, loaded := store.Lookup(address("198.18.0.4"))
			require.True(t, loaded)
			store.advance(testIdle) // the lookup above was a use
			store.sweep()
			require.Equal(t, "idle.test", storage.domainOf(idle))
			require.NoError(t, store.save(saveRequest{}))
			require.Equal(t, "", storage.domainOf(idle))
		}
		_, loaded := store.Lookup(idle)
		require.False(t, loaded)
		if storage == nil {
			_, loaded = store.Lookup(queried)
			require.True(t, loaded, "a query keeps a record")
			_, loaded = store.Lookup(connected)
			require.True(t, loaded, "a connection keeps a record")
		}
		// the address is not taken again at once: the position goes on
		require.Equal(t, address("198.18.0.5"), mustCreate(t, store, "new.test"))
		require.Equal(t, address("198.18.0.6"), mustCreate(t, store, "idle.test"))
	}
}

func TestRecordUsedWhileItIsRemoved(t *testing.T) {
	t.Parallel()
	storage := newFakeStorage()
	store := newTestStore(t, storage, "198.18.0.0/15", "")
	idle := mustCreate(t, store, "idle.test")
	require.NoError(t, store.save(saveRequest{}))
	store.advance(testIdle)
	store.sweep()
	// a connection arrives while the removal is being written
	storage.onSave = func() {
		storage.onSave = nil
		store.advance(1)
		_, loaded := store.Lookup(idle)
		require.True(t, loaded)
	}
	require.NoError(t, store.save(saveRequest{}))
	require.Equal(t, "", storage.domainOf(idle))
	domain, loaded := store.Lookup(idle)
	require.True(t, loaded, "the record stays")
	require.Equal(t, "idle.test", domain)
	require.NoError(t, store.save(saveRequest{}))
	require.Equal(t, "idle.test", storage.domainOf(idle), "and is saved again")
}

func TestCrashDoesNotBringARemovedRecordBack(t *testing.T) {
	t.Parallel()
	storage := newFakeStorage()
	// 13 addresses: .2 to .14
	store := newTestStore(t, storage, "198.18.0.0/28", "")
	var first netip.Addr
	for i := range 13 {
		next := mustCreate(t, store, fmt.Sprint("old-", i, ".test"))
		if i == 0 {
			first = next
		}
		store.advance(1)
	}
	require.NoError(t, store.save(saveRequest{}))
	// the range is full: the record unused longest makes room, its address goes to the new domain
	reused := mustCreate(t, store, "new.test")
	require.Equal(t, first, reused)
	// a crash before "new.test" is saved must not leave "old-0.test" on its address
	store = newTestStore(t, storage.crash(), "198.18.0.0/28", "")
	_, loaded := store.Lookup(reused)
	require.False(t, loaded)
}

func TestFullRangeKeepsRecordsInUse(t *testing.T) {
	t.Parallel()
	for _, storage := range []*fakeStorage{nil, newFakeStorage()} {
		// 61 addresses
		store := newTestStore(t, storage, "198.18.0.0/26", "")
		hot := mustCreate(t, store, "hot.test")
		for i := range 500 {
			store.advance(1)
			next := mustCreate(t, store, fmt.Sprint("name-", i, ".test"))
			require.NotEqual(t, hot, next, "an address in use is not given to another domain")
			if i%10 == 0 {
				require.Equal(t, hot, mustCreate(t, store, "hot.test"))
			}
		}
		domain, loaded := store.Lookup(hot)
		require.True(t, loaded)
		require.Equal(t, "hot.test", domain)
	}
}

func TestRecordLimit(t *testing.T) {
	t.Parallel()
	for _, storage := range []*fakeStorage{nil, newFakeStorage()} {
		store := newTestStore(t, storage, "198.18.0.0/15", "")
		store.pool4.limit = 100
		store.pool4.max = 200
		// .2 to .76, then .77 to .151 half of protectTime later
		for i := range 150 {
			if i == 75 {
				store.advance(testProtect / 2)
			}
			mustCreate(t, store, fmt.Sprint("name-", i, ".test"))
		}
		older := func() (count int) {
			for offset := range store.pool4.byOffset {
				if offset < 77 {
					count++
				}
			}
			return
		}
		store.sweep()
		require.NoError(t, store.save(saveRequest{}))
		require.Len(t, store.pool4.byOffset, 150, "records used within protectTime stay")
		store.advance(testProtect/2 + 10)
		store.sweep()
		require.NoError(t, store.save(saveRequest{}))
		require.Len(t, store.pool4.byOffset, 88, "down to 7/8 of the limit")
		require.Equal(t, 13, older(), "the ones unused longest go")
		require.Len(t, store.pool4.byName, 88)
		if storage != nil {
			require.Equal(t, 88, storage.records())
		}
	}
}

func TestLoadFileOfOlderVersion(t *testing.T) {
	t.Parallel()
	ranges := adapter.FakeIPMetadata{Inet4Range: netip.MustParsePrefix("198.18.0.0/15")}
	t.Run("clean stop", func(t *testing.T) {
		t.Parallel()
		storage := newFakeStorage()
		storage.domainIndex = true
		storage.table[address("198.18.0.2")] = "a.test"
		storage.table[address("198.18.0.3")] = "B.test"
		storage.table[address("10.0.0.1")] = "other-range.test"
		storage.table[address("198.18.0.1")] = "never-given.test"
		storage.cleanKey = &adapter.FakeIPMetadata{Inet4Range: ranges.Inet4Range, Inet4Current: address("198.18.0.3")}
		store := newTestStore(t, storage, "198.18.0.0/15", "")
		require.False(t, storage.domainIndex)
		require.Equal(t, 2, storage.records(), "records outside the range are removed")
		require.Equal(t, address("198.18.0.2"), mustCreate(t, store, "a.test"))
		require.Equal(t, address("198.18.0.3"), mustCreate(t, store, "b.test"))
		require.Equal(t, address("198.18.0.4"), mustCreate(t, store, "c.test"))
	})
	t.Run("position saved by a version that ran later", func(t *testing.T) {
		t.Parallel()
		// this version stopped at .3, then an older one gave out .4 and .5 and stopped cleanly
		storage := newFakeStorage()
		for i, domain := range []string{"a.test", "b.test", "c.test", "d.test"} {
			storage.table[address(fmt.Sprint("198.18.0.", i+2))] = domain
		}
		storage.cursor = &adapter.FakeIPMetadata{Inet4Range: ranges.Inet4Range, Inet4Current: address("198.18.0.3")}
		storage.cleanKey = &adapter.FakeIPMetadata{Inet4Range: ranges.Inet4Range, Inet4Current: address("198.18.0.5")}
		store := newTestStore(t, storage, "198.18.0.0/15", "")
		require.Equal(t, address("198.18.0.6"), mustCreate(t, store, "new.test"))
	})
	t.Run("position behind the addresses in use", func(t *testing.T) {
		t.Parallel()
		// an older version was killed: the position it saved last is far behind
		storage := newFakeStorage()
		for i := range 40 {
			storage.table[address(fmt.Sprint("198.18.0.", i+2))] = fmt.Sprint("name-", i, ".test")
		}
		storage.cursor = &adapter.FakeIPMetadata{Inet4Range: ranges.Inet4Range, Inet4Current: address("198.18.0.6")}
		store := newTestStore(t, storage, "198.18.0.0/15", "")
		require.Equal(t, address("198.18.0.42"), mustCreate(t, store, "new.test"), "addresses in use are stepped over")
	})
	t.Run("no position", func(t *testing.T) {
		t.Parallel()
		storage := newFakeStorage()
		storage.table[address("198.18.0.2")] = "a.test"
		storage.table[address("198.18.0.9")] = "b.test"
		store := newTestStore(t, storage, "198.18.0.0/15", "")
		require.Equal(t, address("198.18.0.10"), mustCreate(t, store, "new.test"), "after the last address in use")
		require.Equal(t, address("198.18.0.9"), mustCreate(t, store, "b.test"))
	})
	t.Run("position of another range", func(t *testing.T) {
		t.Parallel()
		storage := newFakeStorage()
		storage.table[address("198.18.0.2")] = "a.test"
		storage.cursor = &adapter.FakeIPMetadata{Inet4Range: netip.MustParsePrefix("198.18.0.0/16"), Inet4Current: address("198.18.0.200")}
		store := newTestStore(t, storage, "198.18.0.0/15", "")
		require.Equal(t, address("198.18.0.3"), mustCreate(t, store, "new.test"))
	})
	t.Run("a domain with two addresses", func(t *testing.T) {
		t.Parallel()
		storage := newFakeStorage()
		storage.table[address("198.18.0.2")] = "twice.test"
		storage.table[address("198.18.0.3")] = "other.test"
		storage.table[address("198.18.0.4")] = "Twice.test"
		storage.cleanKey = &adapter.FakeIPMetadata{Inet4Range: ranges.Inet4Range, Inet4Current: address("198.18.0.4")}
		store := newTestStore(t, storage, "198.18.0.0/15", "")
		require.Equal(t, address("198.18.0.4"), mustCreate(t, store, "twice.test"), "the later address is given out")
		for _, old := range []string{"198.18.0.2", "198.18.0.4"} {
			domain, loaded := store.Lookup(address(old))
			require.True(t, loaded)
			require.Equal(t, "twice.test", domain, "both lead to the domain")
		}
	})
	t.Run("the ring has wrapped", func(t *testing.T) {
		t.Parallel()
		// .2 was given out after .14: it is the later one
		storage := newFakeStorage()
		storage.table[address("198.18.0.14")] = "twice.test"
		storage.table[address("198.18.0.2")] = "twice.test"
		storage.cleanKey = &adapter.FakeIPMetadata{Inet4Range: netip.MustParsePrefix("198.18.0.0/28"), Inet4Current: address("198.18.0.2")}
		store := newTestStore(t, storage, "198.18.0.0/28", "")
		require.Equal(t, address("198.18.0.2"), mustCreate(t, store, "twice.test"))
		require.Equal(t, address("198.18.0.3"), mustCreate(t, store, "new.test"))
	})
}

func TestRecreatedStorageGetsTheTableAgain(t *testing.T) {
	t.Parallel()
	storage := newFakeStorage()
	store := newTestStore(t, storage, "198.18.0.0/15", "")
	for i := range 20 {
		mustCreate(t, store, fmt.Sprint("name-", i, ".test"))
	}
	require.NoError(t, store.save(saveRequest{}))
	// the cache file was damaged and recreated
	storage.access.Lock()
	clear(storage.table)
	storage.cursor = nil
	storage.generation++
	storage.access.Unlock()
	require.NoError(t, store.save(saveRequest{}))
	require.Equal(t, 20, storage.records())
	require.NotNil(t, storage.cursor)
}

func TestReset(t *testing.T) {
	t.Parallel()
	storage := newFakeStorage()
	store := newTestStore(t, storage, "198.18.0.0/15", "")
	old := mustCreate(t, store, "a.test")
	mustCreate(t, store, "b.test")
	require.NoError(t, store.save(saveRequest{}))
	require.NoError(t, store.Reset())
	require.Equal(t, 0, storage.records())
	_, loaded := store.Lookup(old)
	require.False(t, loaded)
	require.Equal(t, address("198.18.0.4"), mustCreate(t, store, "a.test"), "clients may still hold the old addresses")
	require.NoError(t, store.save(saveRequest{}))
	require.Equal(t, 1, storage.records())
}

func TestIPv6Range(t *testing.T) {
	t.Parallel()
	storage := newFakeStorage()
	// 5 addresses: ::2 to ::6
	store := newTestStore(t, storage, "", "2001:2::/125")
	var given []netip.Addr
	for i := range 5 {
		next, err := store.Create(fmt.Sprint("name-", i, ".test"), true)
		require.NoError(t, err)
		given = append(given, next)
		store.advance(1)
	}
	require.Equal(t, address("2001:2::2"), given[0])
	require.Equal(t, address("2001:2::6"), given[4])
	next, err := store.Create("new.test", true)
	require.NoError(t, err)
	require.Equal(t, given[0], next)
	require.NoError(t, store.Close())
	store = newTestStore(t, storage, "", "2001:2::/125")
	domain, loaded := store.Lookup(given[4])
	require.True(t, loaded)
	require.Equal(t, "name-4.test", domain)

	// a wide range: the offsets cover its start
	store = newTestStore(t, nil, "", "fc00::/18")
	_, loaded = store.Lookup(address("fc00:0:0:1::2"))
	require.False(t, loaded)
	_, loaded = store.Lookup(address("fc00::1:0:0:2"))
	require.False(t, loaded)
}

// The clock is read before a sweep looks at the records: a record used after that must not
// look unused for ages.
func TestSweepKeepsRecordUsedAfterItsClockReading(t *testing.T) {
	t.Parallel()
	for _, storage := range []*fakeStorage{nil, newFakeStorage()} {
		store := newTestStore(t, storage, "198.18.0.0/15", "")
		given := mustCreate(t, store, "busy.test")
		require.NoError(t, store.save(saveRequest{}))
		// used one tick after the clock reading of the sweep
		store.recordAt(given).lastUse.Store(uint64(store.now()+1) << 32)
		store.sweep()
		require.NoError(t, store.save(saveRequest{}))
		require.Equal(t, "busy.test", store.domainAt(given))
		store.pool4.limit = 0
		store.sweep()
		require.NoError(t, store.save(saveRequest{}))
		require.Equal(t, "busy.test", store.domainAt(given), "nor does it give way to keep the number of records down")
	}
}

func TestRecordsUsedWithinOneTickGiveWayInOrderOfUse(t *testing.T) {
	t.Parallel()
	for _, storage := range []*fakeStorage{nil, newFakeStorage()} {
		// 29 addresses, the clock stands still
		store := newTestStore(t, storage, "198.18.0.0/27", "")
		hot := mustCreate(t, store, "hot.test")
		for i := range 300 {
			next := mustCreate(t, store, fmt.Sprint("name-", i, ".test"))
			require.NotEqual(t, hot, next, "after ", i, " names")
			if i%10 == 0 {
				require.Equal(t, hot, mustCreate(t, store, "hot.test"))
			}
		}
	}
}

func TestRecordsOfWideRangeAreBounded(t *testing.T) {
	t.Parallel()
	// the offsets cover 2^32 addresses of the range: it is never full
	store := newTestStore(t, nil, "", "fc00::/18")
	store.pool6.limit = 100
	store.pool6.max = 200
	for i := range 2000 {
		_, err := store.Create(fmt.Sprint("name-", i, ".test"), true)
		require.NoError(t, err)
		require.LessOrEqual(t, len(store.pool6.byOffset), 200, "records used within protectTime make room too")
	}
	store.advance(testProtect)
	store.sweep()
	require.Len(t, store.pool6.byOffset, 88)
}

func TestReserveIsExtendedWhenHalfUsed(t *testing.T) {
	t.Parallel()
	storage := newFakeStorage()
	store := newTestStore(t, storage, "198.18.0.0/15", "")
	first := storage.cursor.Inet4Current
	for i := range reserveStep/2 - 1 {
		mustCreate(t, store, fmt.Sprint("a-", i, ".test"))
	}
	require.True(t, store.savePending())
	require.NoError(t, store.save(saveRequest{}))
	require.Equal(t, first, storage.cursor.Inet4Current, "more than half of the reserve is left")
	mustCreate(t, store, "b-0.test")
	mustCreate(t, store, "b-1.test")
	require.NoError(t, store.save(saveRequest{}))
	require.True(t, first.Less(storage.cursor.Inet4Current), "the save in the background moves the reserve on")
	saves := storage.saves
	require.False(t, store.savePending())
	require.NoError(t, store.save(saveRequest{}))
	require.Equal(t, saves, storage.saves, "nothing to write: no write")
}

func TestQueriesWaitingForReserveShareOneSave(t *testing.T) {
	t.Parallel()
	storage := newFakeStorage()
	store := newTestStore(t, storage, "198.18.0.0/15", "")
	store.pool4.budget = 0
	saves := storage.saves
	var group sync.WaitGroup
	for worker := range 64 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := store.Create(fmt.Sprint("name-", worker, ".test"), false)
			if err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	require.LessOrEqual(t, storage.saves-saves, 3, "not one save per query")
}

func TestAllocationWhileSaveIsWritten(t *testing.T) {
	t.Parallel()
	storage := newFakeStorage()
	store := newTestStore(t, storage, "198.18.0.0/15", "")
	given := make(map[netip.Addr]bool)
	for round := range 40 {
		for i := range 300 {
			given[mustCreate(t, store, fmt.Sprint("a-", round, "-", i, ".test"))] = true
		}
		// queries arrive while the save is written: they use what is left of the old reserve
		storage.onSave = func() {
			storage.onSave = nil
			for i := 0; ; i++ {
				next, need, err := store.allocate(store.pool4, fmt.Sprint("b-", round, "-", i, ".test"))
				require.NoError(t, err)
				if need != needNothing {
					break
				}
				given[next] = true
			}
		}
		require.NoError(t, store.save(saveRequest{}))
		last := storage.cursor.Inet4Current
		for next := range given {
			require.False(t, last.Less(next), "the saved position ", last, " is behind ", next)
		}
		require.LessOrEqual(t, store.pool4.budget, store.pool4.step)
	}
	killed := newTestStore(t, storage.crash(), "198.18.0.0/15", "")
	for i := range 3000 {
		require.False(t, given[mustCreate(t, killed, fmt.Sprint("c-", i, ".test"))])
	}
}

func TestAddressesNotSavedAreHeldBackAfterKill(t *testing.T) {
	t.Parallel()
	storage := newFakeStorage()
	// 13 addresses: .2 to .14, all in use and saved
	store := newTestStore(t, storage, "198.18.0.0/28", "")
	for i := range 13 {
		mustCreate(t, store, fmt.Sprint("old-", i, ".test"))
		store.advance(1)
	}
	require.NoError(t, store.save(saveRequest{}))
	lost := mustCreate(t, store, "lost.test") // takes the place of old-0, is not saved
	require.Equal(t, address("198.18.0.2"), lost)

	storage = storage.crash()
	store = newTestStore(t, storage, "198.18.0.0/28", "")
	_, loaded := store.Lookup(lost)
	require.False(t, loaded)
	for i := range 30 {
		next := mustCreate(t, store, fmt.Sprint("new-", i, ".test"))
		require.NotEqual(t, lost, next, "a client may hold it for lost.test")
		store.advance(1)
	}
	// protectTime after the start it is free again
	store.advance(testProtect)
	store.sweep()
	require.NoError(t, store.save(saveRequest{}))
	var again bool
	for i := range 13 {
		again = again || mustCreate(t, store, fmt.Sprint("late-", i, ".test")) == lost
	}
	require.True(t, again)

	// after a clean stop nothing is held back
	require.NoError(t, store.Close())
	store = newTestStore(t, storage, "198.18.0.0/28", "")
	for _, r := range store.pool4.byOffset {
		require.False(t, r.held())
	}
}

func TestCleanStop(t *testing.T) {
	t.Parallel()
	t.Run("a range that gave out nothing", func(t *testing.T) {
		t.Parallel()
		storage := newFakeStorage()
		store := newTestStore(t, storage, "198.18.0.0/15", "fc00::/18")
		require.NoError(t, store.Close())
		require.Equal(t, address("198.18.0.1"), storage.cleanKey.Inet4Current, "as every version has it")
		require.Equal(t, address("fc00::1"), storage.cleanKey.Inet6Current)
	})
	t.Run("a record about to be removed stays in the storage", func(t *testing.T) {
		t.Parallel()
		storage := newFakeStorage()
		store := newTestStore(t, storage, "198.18.0.0/15", "")
		idle := mustCreate(t, store, "idle.test")
		require.NoError(t, store.save(saveRequest{}))
		store.advance(testIdle)
		store.sweep()
		require.NoError(t, store.Close())
		require.Equal(t, "idle.test", storage.domainOf(idle))
	})
	t.Run("nothing is written after it", func(t *testing.T) {
		t.Parallel()
		storage := newFakeStorage()
		store := newTestStore(t, storage, "198.18.0.0/28", "")
		for i := range 13 {
			mustCreate(t, store, fmt.Sprint("name-", i, ".test"))
		}
		require.NoError(t, store.Close())
		saves := storage.saves
		// a query that found the range full just before the stop
		require.Error(t, store.makeRoom(store.pool4))
		require.Equal(t, saves, storage.saves)
		require.Equal(t, 13, storage.records())
		require.NotNil(t, storage.cleanKey)
	})
}

func TestTableIsKeptWhenTheFileCannotBeChangedAtStart(t *testing.T) {
	t.Parallel()
	storage := newFakeStorage()
	store := newTestStore(t, storage, "198.18.0.0/15", "")
	old := mustCreate(t, store, "a.test")
	mustCreate(t, store, "b.test")
	require.NoError(t, store.Close())

	storage.loadError = errors.New("no space left on device")
	storage.fail = true
	store = newTestStore(t, storage, "198.18.0.0/15", "")
	require.Equal(t, old, mustCreate(t, store, "a.test"), "known domains answer")
	_, err := store.Create("new.test", false)
	require.Error(t, err, "new ones wait for the storage")
	storage.fail = false
	require.Equal(t, address("198.18.0.4"), mustCreate(t, store, "new.test"), "not an address a client holds")
	require.NoError(t, store.save(saveRequest{}))
	require.Equal(t, "a.test", storage.domainOf(old))
}

func TestResetFailure(t *testing.T) {
	t.Parallel()
	storage := newFakeStorage()
	store := newTestStore(t, storage, "198.18.0.0/15", "")
	old := mustCreate(t, store, "a.test")
	require.NoError(t, store.save(saveRequest{}))
	storage.resetError = errors.New("no space left on device")
	require.Error(t, store.Reset())
	domain, loaded := store.Lookup(old)
	require.True(t, loaded, "the memory still agrees with the storage")
	require.Equal(t, "a.test", domain)
}

func TestSecondRangeAddedAfterKill(t *testing.T) {
	t.Parallel()
	storage := newFakeStorage()
	store := newTestStore(t, storage, "198.18.0.0/15", "")
	mustCreate(t, store, "saved.test")
	require.NoError(t, store.save(saveRequest{}))
	lost := mustCreate(t, store, "lost.test")
	// the configuration gets an IPv6 range; the position of the IPv4 range is still valid
	store = newTestStore(t, storage.crash(), "198.18.0.0/15", "fc00::/18")
	for i := range 100 {
		require.NotEqual(t, lost, mustCreate(t, store, fmt.Sprint("new-", i, ".test")))
	}
	first6, err := store.Create("new.test", true)
	require.NoError(t, err)
	require.Equal(t, address("fc00::2"), first6)
}

// The loop saves in the background, and tries again after a failure, without waiting for
// the next new name.
func TestBackgroundSave(t *testing.T) {
	t.Parallel()
	storage := newFakeStorage()
	store := NewStore(context.Background(), logger.NOP(), netip.MustParsePrefix("198.18.0.0/15"), netip.Prefix{})
	store.testStorage = storage
	store.saveRetry = 20 * time.Millisecond
	require.NoError(t, store.Start())
	first := mustCreate(t, store, "a.test")
	require.Eventually(t, func() bool { return storage.domainOf(first) == "a.test" }, 3*time.Second, 5*time.Millisecond)

	storage.access.Lock()
	storage.fail = true
	storage.access.Unlock()
	second := mustCreate(t, store, "b.test")
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, "", storage.domainOf(second))
	storage.access.Lock()
	storage.fail = false
	storage.access.Unlock()
	require.Eventually(t, func() bool { return storage.domainOf(second) == "b.test" }, 3*time.Second, 5*time.Millisecond)

	// a recreated cache file gets the table again without a new name
	storage.access.Lock()
	clear(storage.table)
	storage.generation++
	storage.access.Unlock()
	mustCreate(t, store, "a.test") // a known name: nothing to save by itself
	store.signal()
	require.Eventually(t, func() bool { return storage.records() == 2 }, 3*time.Second, 5*time.Millisecond)
	require.NoError(t, store.Close())
}

// A model of the clients: the address each one was given and holds. Whatever happens,
// crashes included, such an address leads to the domain it was given for or to nothing,
// and is not given to another domain, until the store removes the record by its rules.
func TestClientsNeverReachAnotherDomain(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		prefix  string
		domains int
	}{
		{"198.18.0.0/15", 5000}, // room for everything: the ring never comes around
		{"198.18.0.0/24", 400},  // 253 addresses: the range fills up and wraps
		{"198.18.0.0/28", 40},   // 13 addresses
	} {
		t.Run(test.prefix, func(t *testing.T) {
			t.Parallel()
			for seed := range uint64(20) {
				runClientModel(t, test.prefix, test.domains, seed)
			}
		})
	}
}

func runClientModel(t *testing.T, prefix string, domains int, seed uint64) {
	random := rand.New(rand.NewPCG(seed, 7))
	storage := newFakeStorage()
	held := make(map[netip.Addr]string)  // what clients hold
	saved := make(map[netip.Addr]string) // the part of it that reached the storage
	var store *Store
	start := func() {
		var err error
		store, err = startTestStore(storage, prefix, "")
		require.NoError(t, err)
		store.removed = func(p *pool, r *record) {
			gone := p.address(r.offset)
			if r.held() {
				// held back after a kill for an address given out and not saved: free again
				delete(held, gone)
				return
			}
			require.NotEqual(t, r.domain, storage.domainOf(gone), "a record leaves memory only after it left the storage")
			if held[gone] == r.domain {
				delete(held, gone)
				delete(saved, gone)
			}
		}
		for address, domain := range held {
			loadedDomain, loaded := store.Lookup(address)
			if loaded {
				require.Equal(t, domain, loadedDomain, "seed ", seed, ": ", address, " leads to another domain after a restart")
			} else if store.recordAt(address) == nil {
				// no record and not held back: the process before this one was stopped
				// cleanly after a kill, or released it; the clients ask again
				delete(held, address)
			}
		}
		for address, domain := range saved {
			loadedDomain, loaded := store.Lookup(address)
			require.True(t, loaded, "seed ", seed, ": ", address, " was saved and is lost")
			require.Equal(t, domain, loadedDomain)
		}
	}
	markSaved := func() {
		for address, domain := range held {
			r := store.recordAt(address)
			if r == nil || r.domain != domain {
				continue
			}
			if r.dirty {
				// not in the storage now: new, or used while its removal was written (it
				// is saved again by the next save)
				delete(saved, address)
			} else {
				saved[address] = domain
			}
		}
	}
	save := func(request saveRequest) {
		// while the save is written, clients use addresses and new names arrive
		storage.onSave = func() {
			storage.onSave = nil
			for address := range held {
				if random.IntN(4) == 0 {
					store.Lookup(address)
				}
			}
			for range random.IntN(4) {
				domain := fmt.Sprint("name-", random.IntN(domains), ".test")
				given, need, err := store.allocate(store.pool4, domain)
				if err != nil || need != needNothing {
					break
				}
				if holder, isHeld := held[given]; isHeld {
					require.Equal(t, holder, domain, "seed ", seed, ": ", given, " is given to another domain")
				}
				held[given] = domain
			}
		}
		err := store.save(request)
		storage.onSave = nil
		if err == nil {
			markSaved()
		}
	}
	start()
	for range 3000 {
		switch choice := random.IntN(100); {
		case choice < 60:
			domain := fmt.Sprint("name-", random.IntN(domains), ".test")
			given, err := store.Create(domain, false)
			if err != nil {
				require.True(t, storage.fail, err)
				continue
			}
			if holder, isHeld := held[given]; isHeld {
				require.Equal(t, holder, domain, "seed ", seed, ": ", given, " is given to another domain")
			}
			held[given] = domain
		case choice < 75:
			for address, domain := range held {
				loadedDomain, loaded := store.Lookup(address)
				if loaded {
					require.Equal(t, domain, loadedDomain, "seed ", seed, ": ", address, " leads to another domain")
				} else {
					require.Equal(t, "", saved[address], "seed ", seed, ": ", address, " was saved and is lost")
				}
				break
			}
		case choice < 83:
			store.advance(uint32(random.IntN(testIdle / 4)))
		case choice < 88:
			store.sweep()
		case choice < 94:
			save(saveRequest{})
		case choice < 96:
			storage.fail = !storage.fail
		case choice < 98:
			// a crash
			storage.fail = false
			storage = storage.crash()
			start()
		default:
			// a clean stop
			storage.fail = false
			require.NoError(t, store.Close())
			markSaved()
			start()
		}
	}
}

func TestConcurrentUse(t *testing.T) {
	t.Parallel()
	storage := newFakeStorage()
	// 1021 addresses for 3000 names: the range fills up and makes room all the time
	store := NewStore(context.Background(), logger.NOP(), netip.MustParsePrefix("198.18.0.0/22"), netip.Prefix{})
	store.testStorage = storage
	require.NoError(t, store.Start())
	var group sync.WaitGroup
	for worker := range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			random := rand.New(rand.NewPCG(uint64(worker), 1))
			for range 5000 {
				given, err := store.Create(fmt.Sprint("name-", random.IntN(3000), ".test"), false)
				if err != nil {
					t.Error(err)
					return
				}
				store.Lookup(given)
			}
		}()
	}
	group.Add(1)
	go func() {
		defer group.Done()
		for range 200 {
			store.sweep()
		}
	}()
	group.Wait()
	require.NoError(t, store.Close())
	// after a clean stop the storage holds what the memory holds, and the two indexes agree
	require.Equal(t, len(store.pool4.byOffset), storage.records())
	require.Len(t, store.pool4.byName, len(store.pool4.byOffset))
	for offset, r := range store.pool4.byOffset {
		require.Equal(t, r.domain, storage.domainOf(store.pool4.address(offset)))
		require.Same(t, r, store.pool4.byName[r.domain])
	}
}

func BenchmarkStore(b *testing.B) {
	// the real clock, as in sing-box
	store := NewStore(context.Background(), logger.NOP(), netip.MustParsePrefix("198.18.0.0/15"), netip.Prefix{})
	err := store.Start()
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()
	const names = 30000
	domains := make([]string, names)
	addresses := make([]netip.Addr, names)
	for i := range domains {
		domains[i] = fmt.Sprint("name-", i, ".example.com")
		addresses[i], _ = store.Create(domains[i], false)
	}
	b.Run("domain to address", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			store.Create(domains[i%names], false)
		}
	})
	b.Run("address to domain", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; b.Loop(); i++ {
			store.Lookup(addresses[i%names])
		}
	})
}

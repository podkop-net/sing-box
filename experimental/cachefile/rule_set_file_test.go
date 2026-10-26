package cachefile

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// A big list changed again and again takes its size once in the file beside the cache file,
// and the cache file stays small; what is saved comes back across a reopen.
func TestRuleSetFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	cacheFile := openTestCacheFile(t, path)
	list := bytes.Repeat([]byte("203.0.113.0/24\n"), 300000)
	for round := byte(0); round < 4; round++ {
		list[0] = '0' + round
		require.NoError(t, cacheFile.SaveRuleSet("big", &adapter.SavedBinary{Content: list, LastUpdated: time.Unix(100+int64(round), 0), LastEtag: "e"}))
	}
	require.NoError(t, cacheFile.Close())
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Less(t, info.Size(), int64(len(list)/4), "the list is not in the cache file")
	entries, err := os.ReadDir(path + ruleSetFileSuffix)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	cacheFile = openTestCacheFile(t, path)
	defer cacheFile.Close()
	saved := cacheFile.LoadRuleSet("big")
	require.NotNil(t, saved)
	require.Equal(t, list, saved.Content)
	require.True(t, time.Unix(103, 0).Equal(saved.LastUpdated))
	require.Equal(t, "e", saved.LastEtag)
	require.Nil(t, cacheFile.LoadRuleSet("other"))
}

// A rule set an earlier version kept in the database is read from there until it is saved
// again; the save moves it into its file.
func TestRuleSetFileFromDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	cacheFile := openTestCacheFile(t, path)
	old, err := (&adapter.SavedBinary{Content: []byte("old.lab.example\n"), LastUpdated: time.Unix(50, 0)}).MarshalBinary()
	require.NoError(t, err)
	require.NoError(t, cacheFile.batch(func(tx *bbolt.Tx) error {
		bucket, err := cacheFile.createBucket(tx, bucketRuleSet)
		if err != nil {
			return err
		}
		return bucket.Put([]byte("lists"), old)
	}))
	saved := cacheFile.LoadRuleSet("lists")
	require.NotNil(t, saved)
	require.Equal(t, "old.lab.example\n", string(saved.Content))

	require.NoError(t, cacheFile.SaveRuleSet("lists", &adapter.SavedBinary{Content: []byte("new.lab.example\n"), LastUpdated: time.Unix(60, 0)}))
	require.Equal(t, "new.lab.example\n", string(cacheFile.LoadRuleSet("lists").Content))
	require.NoError(t, cacheFile.view(func(tx *bbolt.Tx) error {
		require.Nil(t, cacheFile.bucket(tx, bucketRuleSet).Get([]byte("lists")), "the record of the earlier version is left")
		return nil
	}))
	require.NoError(t, cacheFile.Close())
}

// A file that is not whole (a write cut by a power loss) is not read: the rule set is
// downloaded again. A reopen removes the files no record names and the writes that were
// cut, and keeps those of every cache ID.
func TestRuleSetFileBroken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	cacheFile := openTestCacheFile(t, path)
	require.NoError(t, cacheFile.SaveRuleSet("lists", &adapter.SavedBinary{Content: []byte("one.lab.example\ntwo.lab.example\n")}))
	directory := path + ruleSetFileSuffix
	file := filepath.Join(directory, ruleSetFileName(nil, "lists"))
	require.NoError(t, os.WriteFile(file, []byte("one.lab.example\n"), 0o644))
	require.Nil(t, cacheFile.LoadRuleSet("lists"))
	require.NoError(t, cacheFile.Close())

	other := New(context.Background(), option.CacheFileOptions{Enabled: true, Path: path, CacheID: "other"})
	require.NoError(t, other.Start(adapter.StartStateInitialize))
	require.NoError(t, other.SaveRuleSet("lists", &adapter.SavedBinary{Content: []byte("three.lab.example\n")}))
	require.NoError(t, other.Close())

	require.NoError(t, os.WriteFile(filepath.Join(directory, "gone-01020304"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(file+ruleSetFileWriting, []byte("x"), 0o644))
	cacheFile = openTestCacheFile(t, path)
	defer cacheFile.Close()
	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	require.ElementsMatch(t, []string{ruleSetFileName(nil, "lists"), ruleSetFileName([]byte("\x00other"), "lists")}, names)
}

// File names keep what a file name can have of a tag and differ for every tag and cache ID.
func TestRuleSetFileName(t *testing.T) {
	require.Regexp(t, `^main-subnets_list\.lst-[0-9a-f]{8}$`, ruleSetFileName(nil, "main-subnets/list.lst"))
	require.NotEqual(t, ruleSetFileName(nil, "a/b"), ruleSetFileName(nil, "a_b"))
	require.NotEqual(t, ruleSetFileName(nil, "a"), ruleSetFileName([]byte("\x00x"), "a"))
}

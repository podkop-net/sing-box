package cachefile

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service/filemanager"
)

// The content of a remote rule set is kept in a file of its own beside the cache file
// (podkop-engine); the bucket rule_set_file keeps the rest of what is saved of it and the
// size of the content. In the database a list of megabytes took three times its size: bbolt
// writes a changed value anew, keeps the pages it freed and never gives them back to the
// file system, which on a router is flash or RAM. The write also took two copies of the
// list in memory, the value and the pages it was written into.
//
// The file is written first and renamed into place, then the record: a file whose size is
// not the one its record tells (a write cut by a power loss) is not read, and the rule set
// is downloaded again. A record in the bucket rule_set of an earlier version is read until
// the rule set is saved again; the save deletes it. An earlier version finds no record
// there and downloads the list.
var bucketRuleSetFile = []byte("rule_set_file")

// ruleSetFileSuffix names the directory of the files: the path of the cache file with it.
const ruleSetFileSuffix = ".rule-sets"

// a file being written has this added to its name until it is complete
const ruleSetFileWriting = ".new"

func (c *CacheFile) ruleSetDirectory() string {
	return c.path + ruleSetFileSuffix
}

// ruleSetFileName is the name of the file of a rule set of a cache ID: the tag with what a
// file name cannot have replaced, and a hash of both, as tags differ only in such
// characters, and two cache IDs may have the same tag.
func ruleSetFileName(cacheID []byte, tag string) string {
	sum := sha256.Sum256(append(append([]byte{}, cacheID...), "\x00"+tag...))
	var name strings.Builder
	for _, char := range tag {
		if name.Len() >= 64 {
			break
		}
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9', char == '-', char == '_', char == '.':
			name.WriteRune(char)
		default:
			name.WriteByte('_')
		}
	}
	return name.String() + "-" + hex.EncodeToString(sum[:4])
}

// ruleSetRecord is what the bucket keeps of a rule set: the size of its content, then the
// rest of adapter.SavedBinary as it writes itself, without the content.
func ruleSetRecord(set *adapter.SavedBinary) ([]byte, error) {
	rest, err := (&adapter.SavedBinary{LastUpdated: set.LastUpdated, LastEtag: set.LastEtag}).MarshalBinary()
	if err != nil {
		return nil, err
	}
	record := binary.AppendUvarint([]byte{1}, uint64(len(set.Content)))
	return append(record, rest...), nil
}

func parseRuleSetRecord(record []byte) (*adapter.SavedBinary, uint64, error) {
	reader := bytes.NewReader(record)
	version, err := reader.ReadByte()
	if err != nil {
		return nil, 0, err
	}
	if version != 1 {
		return nil, 0, E.New("unknown version of a rule-set record: ", version)
	}
	size, err := binary.ReadUvarint(reader)
	if err != nil {
		return nil, 0, err
	}
	rest, err := io.ReadAll(reader)
	if err != nil {
		return nil, 0, err
	}
	var saved adapter.SavedBinary
	err = saved.UnmarshalBinary(rest)
	if err != nil {
		return nil, 0, err
	}
	return &saved, size, nil
}

// loadRuleSetFile reads a rule set saved in a file; found tells that it has a record,
// which is then the only place it is read from (nil when its file is not whole).
func (c *CacheFile) loadRuleSetFile(tag string) (saved *adapter.SavedBinary, found bool) {
	var record []byte
	_ = c.view(func(t *bbolt.Tx) error {
		bucket := c.bucket(t, bucketRuleSetFile)
		if bucket == nil {
			return nil
		}
		record = bytes.Clone(bucket.Get([]byte(tag)))
		return nil
	})
	if record == nil {
		return nil, false
	}
	// the cache file of this line has no logger: a rule set whose file cannot be read is
	// downloaded again, as one never saved
	saved, size, err := parseRuleSetRecord(record)
	if err != nil {
		return nil, true
	}
	path := filepath.Join(c.ruleSetDirectory(), ruleSetFileName(c.cacheID, tag))
	content, err := os.ReadFile(path)
	if err != nil || uint64(len(content)) != size {
		return nil, true
	}
	saved.Content = content
	return saved, true
}

// saveRuleSetFile writes the content of a rule set into its file, then its record; the
// record of an earlier version goes.
func (c *CacheFile) saveRuleSetFile(tag string, set *adapter.SavedBinary) error {
	record, err := ruleSetRecord(set)
	if err != nil {
		return err
	}
	directory := c.ruleSetDirectory()
	err = filemanager.MkdirAll(c.ctx, directory, 0o755)
	if err != nil {
		return err
	}
	path := filepath.Join(directory, ruleSetFileName(c.cacheID, tag))
	writing := path + ruleSetFileWriting
	file, err := filemanager.OpenFile(c.ctx, writing, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, err = file.Write(set.Content)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(writing, path)
	}
	if err != nil {
		_ = os.Remove(writing)
		return err
	}
	return c.batch(func(t *bbolt.Tx) error {
		bucket, err := c.createBucket(t, bucketRuleSetFile)
		if err != nil {
			return err
		}
		err = bucket.Put([]byte(tag), record)
		if err != nil {
			return err
		}
		if legacy := c.bucket(t, bucketRuleSet); legacy != nil && legacy.Get([]byte(tag)) != nil {
			return legacy.Delete([]byte(tag))
		}
		return nil
	})
}

// pruneRuleSetFiles removes the files of the directory that no record names (of any cache
// ID), and files whose write was cut.
func (c *CacheFile) pruneRuleSetFiles(db *bbolt.DB) {
	entries, err := os.ReadDir(c.ruleSetDirectory())
	if err != nil {
		return
	}
	named := make(map[string]bool)
	_ = db.View(func(t *bbolt.Tx) error {
		collect := func(cacheID []byte, bucket *bbolt.Bucket) {
			if bucket == nil {
				return
			}
			_ = bucket.ForEach(func(tag []byte, _ []byte) error {
				named[ruleSetFileName(cacheID, string(tag))] = true
				return nil
			})
		}
		collect(nil, t.Bucket(bucketRuleSetFile))
		return t.ForEach(func(name []byte, bucket *bbolt.Bucket) error {
			if len(name) > 0 && name[0] == 0 {
				collect(bytes.Clone(name), bucket.Bucket(bucketRuleSetFile))
			}
			return nil
		})
	})
	for _, entry := range entries {
		if !named[entry.Name()] {
			_ = os.Remove(filepath.Join(c.ruleSetDirectory(), entry.Name()))
		}
	}
}

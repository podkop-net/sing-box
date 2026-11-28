package cachefile

import (
	"bytes"
	"net/netip"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
)

// What the FakeIP store that keeps the whole map in memory (dns/transport/fakeip.TableStore)
// needs of the cache file: the table read once at start, then only the changes written.
// It keeps upstream's records (the address table of bucketFakeIP, the position under
// keyMetadata); upstream's methods in fakeip.go stay as upstream has them.

// the allocation position of a store that keeps the map in memory, saved ahead of the
// addresses given out; a bucket of its own keeps the write small. Its name has the prefix
// that start keeps the buckets of.
var bucketFakeIPCursor = []byte(fakeipBucketPrefix + "cursor")

// FakeIPLoadTable gives the saved addresses to a store that keeps the whole map in memory
// and returns the saved allocation position, if there is one. Such a store needs only the
// table of addresses: the index of domains, which it builds itself, is removed, and so are
// the records load refuses.
//
// The position under keyMetadata, where every version keeps it, comes first (clean is true
// then): this store writes it only on a clean stop and removes it as soon as addresses are
// given out again, and upstream's store writes it ahead of the addresses it gives out
// (FakeIPReserve); either way no address past it has been given out. Else the position this
// store saved ahead of the addresses given out.
//
// The table is read first and the file is changed after that: what was read is valid even
// if the change fails.
func (c *CacheFile) FakeIPLoadTable(load func(address netip.Addr, domain string) bool) (*adapter.FakeIPMetadata, bool, error) {
	var (
		metadata *adapter.FakeIPMetadata
		clean    bool
		refused  [][]byte
	)
	err := c.view(func(tx *bbolt.Tx) error {
		var metadataBinary []byte
		bucket := tx.Bucket(bucketFakeIP)
		if bucket != nil {
			metadataBinary = bucket.Get(keyMetadata)
			clean = len(metadataBinary) > 0
		}
		if !clean {
			if cursor := tx.Bucket(bucketFakeIPCursor); cursor != nil {
				metadataBinary = cursor.Get(keyMetadata)
			}
		}
		if len(metadataBinary) > 0 {
			var saved adapter.FakeIPMetadata
			if saved.UnmarshalBinary(metadataBinary) == nil {
				metadata = &saved
			} else {
				clean = false
			}
		}
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(key []byte, value []byte) error {
			if bytes.Equal(key, keyMetadata) {
				return nil
			}
			address, isAddress := netip.AddrFromSlice(key)
			if !isAddress || !load(address, string(value)) {
				refused = append(refused, append([]byte(nil), key...))
			}
			return nil
		})
	})
	if err != nil {
		return nil, false, err
	}
	err = c.update(func(tx *bbolt.Tx) error {
		for _, bucketName := range [][]byte{bucketFakeIPDomain4, bucketFakeIPDomain6} {
			if tx.Bucket(bucketName) == nil {
				continue
			}
			err := tx.DeleteBucket(bucketName)
			if err != nil {
				return err
			}
		}
		bucket := tx.Bucket(bucketFakeIP)
		if bucket == nil {
			return nil
		}
		for _, key := range append(refused, keyMetadata) {
			err := bucket.Delete(key)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return metadata, clean, err
}

// FakeIPSaveChanges writes and removes addresses and saves the allocation position in one
// transaction. clean: the store stops, the position is exact and is also written where
// versions that do not know the cursor bucket read it. Any other save removes it from
// there: addresses are given out again.
func (c *CacheFile) FakeIPSaveChanges(puts map[netip.Addr]string, deletes []netip.Addr, metadata *adapter.FakeIPMetadata, clean bool) error {
	metadataBinary, err := metadata.MarshalBinary()
	if err != nil {
		return err
	}
	return c.update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketFakeIP)
		if err != nil {
			return err
		}
		for _, address := range deletes {
			err = bucket.Delete(address.AsSlice())
			if err != nil {
				return err
			}
		}
		for address, domain := range puts {
			err = bucket.Put(address.AsSlice(), []byte(domain))
			if err != nil {
				return err
			}
		}
		if clean {
			err = bucket.Put(keyMetadata, metadataBinary)
		} else {
			err = bucket.Delete(keyMetadata)
		}
		if err != nil {
			return err
		}
		cursor, err := tx.CreateBucketIfNotExists(bucketFakeIPCursor)
		if err != nil {
			return err
		}
		return cursor.Put(keyMetadata, metadataBinary)
	})
}

// FakeIPGeneration returns a value that changes when everything saved before is gone: the
// database itself, read as view, batch and update read it. resetDB replaces a damaged
// database with a new one, bbolt.Open gives a new *bbolt.DB, or with none (nil) when that
// fails. A caller that keeps the value it compares with keeps that database from being
// freed, so no later one can have its address.
func (c *CacheFile) FakeIPGeneration() any {
	return c.database()
}

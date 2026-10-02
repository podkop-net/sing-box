package cachefile

import (
	"bytes"
	"net/netip"
	"os"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

const fakeipBucketPrefix = "fakeip_"

var (
	bucketFakeIP        = []byte(fakeipBucketPrefix + "address")
	bucketFakeIPDomain4 = []byte(fakeipBucketPrefix + "domain4")
	bucketFakeIPDomain6 = []byte(fakeipBucketPrefix + "domain6")
	keyMetadata         = []byte(fakeipBucketPrefix + "metadata")
	// the allocation position of a store that keeps the map in memory, saved ahead of
	// the addresses given out; a bucket of its own keeps the write small
	bucketFakeIPCursor = []byte(fakeipBucketPrefix + "cursor")
)

// FakeIPLoadTable gives the saved addresses to a store that keeps the whole map in memory
// and returns the saved allocation position, if there is one. Such a store needs only the
// table of addresses: the index of domains, which it builds itself, is removed, and so are
// the records load refuses.
//
// The position saved on a clean stop, where every version keeps it, comes first (clean is
// true then): it is written only on a clean stop and removed as soon as addresses are given
// out again, so if it is there, the last process to stop wrote it and no address was given
// out since. Else the position saved ahead of the addresses given out.
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

// FakeIPGeneration changes when the cache file was damaged and recreated: everything
// saved before is gone.
func (c *CacheFile) FakeIPGeneration() uint64 {
	return c.generation.Load()
}

func (c *CacheFile) FakeIPMetadata() *adapter.FakeIPMetadata {
	var metadata adapter.FakeIPMetadata
	err := c.batch(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketFakeIP)
		if bucket == nil {
			return os.ErrNotExist
		}
		metadataBinary := bucket.Get(keyMetadata)
		if len(metadataBinary) == 0 {
			return os.ErrInvalid
		}
		err := bucket.Delete(keyMetadata)
		if err != nil {
			return err
		}
		return metadata.UnmarshalBinary(metadataBinary)
	})
	if err != nil {
		return nil
	}
	return &metadata
}

func (c *CacheFile) FakeIPSaveMetadata(metadata *adapter.FakeIPMetadata) error {
	return c.batch(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketFakeIP)
		if err != nil {
			return err
		}
		metadataBinary, err := metadata.MarshalBinary()
		if err != nil {
			return err
		}
		return bucket.Put(keyMetadata, metadataBinary)
	})
}

func (c *CacheFile) FakeIPSaveMetadataAsync(metadata *adapter.FakeIPMetadata) {
	c.saveMetadataAccess.Lock()
	defer c.saveMetadataAccess.Unlock()
	c.saveMetadata = metadata
	if c.saveMetadataTimer == nil {
		c.saveMetadataTimer = time.AfterFunc(C.FakeIPMetadataSaveInterval, func() {
			c.saveMetadataAccess.Lock()
			savedMetadata := c.saveMetadata
			c.saveMetadataAccess.Unlock()
			if savedMetadata != nil {
				_ = c.FakeIPSaveMetadata(savedMetadata)
			}
		})
	} else {
		c.saveMetadataTimer.Reset(C.FakeIPMetadataSaveInterval)
	}
}

func (c *CacheFile) FakeIPStore(address netip.Addr, domain string) error {
	return c.batch(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketFakeIP)
		if err != nil {
			return err
		}
		oldDomain := bucket.Get(address.AsSlice())
		err = bucket.Put(address.AsSlice(), []byte(domain))
		if err != nil {
			return err
		}
		if address.Is4() {
			bucket, err = tx.CreateBucketIfNotExists(bucketFakeIPDomain4)
		} else {
			bucket, err = tx.CreateBucketIfNotExists(bucketFakeIPDomain6)
		}
		if err != nil {
			return err
		}
		if oldDomain != nil {
			if err := bucket.Delete(oldDomain); err != nil {
				return err
			}
		}
		return bucket.Put([]byte(domain), address.AsSlice())
	})
}

func (c *CacheFile) FakeIPStoreAsync(address netip.Addr, domain string, logger logger.Logger) {
	c.saveFakeIPAccess.Lock()
	if oldDomain, loaded := c.saveDomain[address]; loaded {
		if address.Is4() {
			delete(c.saveAddress4, oldDomain)
		} else {
			delete(c.saveAddress6, oldDomain)
		}
	}
	c.saveDomain[address] = domain
	if address.Is4() {
		c.saveAddress4[domain] = address
	} else {
		c.saveAddress6[domain] = address
	}
	c.saveFakeIPAccess.Unlock()
	go func() {
		err := c.FakeIPStore(address, domain)
		if err != nil {
			logger.Warn("save FakeIP cache: ", err)
		}
		c.saveFakeIPAccess.Lock()
		delete(c.saveDomain, address)
		if address.Is4() {
			delete(c.saveAddress4, domain)
		} else {
			delete(c.saveAddress6, domain)
		}
		c.saveFakeIPAccess.Unlock()
	}()
}

func (c *CacheFile) FakeIPLoad(address netip.Addr) (string, bool) {
	c.saveFakeIPAccess.RLock()
	cachedDomain, cached := c.saveDomain[address]
	c.saveFakeIPAccess.RUnlock()
	if cached {
		return cachedDomain, true
	}
	var domain string
	_ = c.view(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketFakeIP)
		if bucket == nil {
			return nil
		}
		domain = string(bucket.Get(address.AsSlice()))
		return nil
	})
	return domain, domain != ""
}

func (c *CacheFile) FakeIPLoadDomain(domain string, isIPv6 bool) (netip.Addr, bool) {
	var (
		cachedAddress netip.Addr
		cached        bool
	)
	c.saveFakeIPAccess.RLock()
	if !isIPv6 {
		cachedAddress, cached = c.saveAddress4[domain]
	} else {
		cachedAddress, cached = c.saveAddress6[domain]
	}
	c.saveFakeIPAccess.RUnlock()
	if cached {
		return cachedAddress, true
	}
	var address netip.Addr
	_ = c.view(func(tx *bbolt.Tx) error {
		var bucket *bbolt.Bucket
		if isIPv6 {
			bucket = tx.Bucket(bucketFakeIPDomain6)
		} else {
			bucket = tx.Bucket(bucketFakeIPDomain4)
		}
		if bucket == nil {
			return nil
		}
		address = M.AddrFromIP(bucket.Get([]byte(domain)))
		return nil
	})
	return address, address.IsValid()
}

func (c *CacheFile) FakeIPReset() error {
	return c.batch(func(tx *bbolt.Tx) error {
		for _, bucketName := range [][]byte{bucketFakeIP, bucketFakeIPDomain4, bucketFakeIPDomain6} {
			if tx.Bucket(bucketName) == nil {
				continue
			}
			err := tx.DeleteBucket(bucketName)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

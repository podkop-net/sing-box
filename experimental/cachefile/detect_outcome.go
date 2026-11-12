package cachefile

import (
	"encoding/binary"
	"time"

	"github.com/sagernet/bbolt"
)

// bucketDetectOutcome keeps what the block detector read of a server (podkop-engine): the time
// of the reading, a flags byte (adapter.DetectNoAnswer, adapter.DetectRefused,
// adapter.DetectFailed), then the fingerprint in use (empty when nothing got through). The key is
// the one the uTLS fallback uses for its choice: the configured fingerprint, the server name and
// the server.
var bucketDetectOutcome = []byte("detect_outcome")

func (c *CacheFile) LoadDetectOutcome(key string) (flags byte, fingerprint string, at time.Time, loaded bool) {
	c.view(func(t *bbolt.Tx) error {
		bucket := c.bucket(t, bucketDetectOutcome)
		if bucket == nil {
			return nil
		}
		value := bucket.Get([]byte(key))
		if len(value) < 9 {
			return nil
		}
		at = time.Unix(int64(binary.BigEndian.Uint64(value[:8])), 0)
		flags = value[8]
		fingerprint = string(value[9:])
		loaded = true
		return nil
	})
	return
}

func (c *CacheFile) StoreDetectOutcome(key string, flags byte, fingerprint string, at time.Time) error {
	return c.batch(func(t *bbolt.Tx) error {
		bucket, err := c.createBucket(t, bucketDetectOutcome)
		if err != nil {
			return err
		}
		value := make([]byte, 9+len(fingerprint))
		binary.BigEndian.PutUint64(value, uint64(at.Unix()))
		value[8] = flags
		copy(value[9:], fingerprint)
		return bucket.Put([]byte(key), value)
	})
}

package cachefile

import (
	"encoding/binary"
	"time"

	"github.com/sagernet/bbolt"
)

// bucketUTLSChoice keeps what the uTLS fingerprint fallback chose for a server (podkop-engine):
// the time of the choice, then the name of the ClientHello chosen.
var bucketUTLSChoice = []byte("utls_choice")

func (c *CacheFile) LoadUTLSChoice(key string) (choice string, at time.Time, loaded bool) {
	c.view(func(t *bbolt.Tx) error {
		bucket := c.bucket(t, bucketUTLSChoice)
		if bucket == nil {
			return nil
		}
		value := bucket.Get([]byte(key))
		if len(value) <= 8 {
			return nil
		}
		at = time.Unix(int64(binary.BigEndian.Uint64(value[:8])), 0)
		choice = string(value[8:])
		loaded = true
		return nil
	})
	return
}

func (c *CacheFile) StoreUTLSChoice(key string, choice string, at time.Time) error {
	return c.batch(func(t *bbolt.Tx) error {
		bucket, err := c.createBucket(t, bucketUTLSChoice)
		if err != nil {
			return err
		}
		value := make([]byte, 8+len(choice))
		binary.BigEndian.PutUint64(value, uint64(at.Unix()))
		copy(value[8:], choice)
		return bucket.Put([]byte(key), value)
	})
}

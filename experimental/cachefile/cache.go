package cachefile

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/bbolt"
	bboltErrors "github.com/sagernet/bbolt/errors"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service/filemanager"
)

var (
	bucketSelected = []byte("selected")
	bucketExpand   = []byte("group_expand")
	bucketMode     = []byte("clash_mode")
	bucketRuleSet  = []byte("rule_set")
	// when each remote rule set was last found up to date (podkop-engine)
	bucketRuleSetChecked = []byte("rule_set_checked")

	bucketNameList = []string{
		string(bucketSelected),
		string(bucketExpand),
		string(bucketMode),
		string(bucketRuleSet),
		string(bucketRuleSetChecked),
		string(bucketRuleSetFile),
		string(bucketUTLSChoice),
		string(bucketRDRC),
	}

	cacheIDDefault = []byte("default")
)

var _ adapter.CacheFile = (*CacheFile)(nil)

type CacheFile struct {
	ctx                context.Context
	path               string
	cacheID            []byte
	storeFakeIP        bool
	storeRDRC          bool
	rdrcTimeout        time.Duration
	DB                 *bbolt.DB
	resetAccess        sync.Mutex
	generation         atomic.Uint64 // counts resetDB: what was saved before is gone
	saveMetadataAccess sync.Mutex
	saveMetadata       *adapter.FakeIPMetadata
	saveMetadataTimer  *time.Timer
	saveFakeIPAccess   sync.RWMutex
	saveDomain         map[netip.Addr]string
	saveAddress4       map[string]netip.Addr
	saveAddress6       map[string]netip.Addr
	saveRDRCAccess     sync.RWMutex
	saveRDRC           map[saveRDRCCacheKey]bool
}

type saveRDRCCacheKey struct {
	TransportName string
	QuestionName  string
	QType         uint16
}

func New(ctx context.Context, options option.CacheFileOptions) *CacheFile {
	var path string
	if options.Path != "" {
		path = options.Path
	} else {
		path = "cache.db"
	}
	var cacheIDBytes []byte
	if options.CacheID != "" {
		cacheIDBytes = append([]byte{0}, []byte(options.CacheID)...)
	}
	var rdrcTimeout time.Duration
	if options.StoreRDRC {
		if options.RDRCTimeout > 0 {
			rdrcTimeout = time.Duration(options.RDRCTimeout)
		} else {
			rdrcTimeout = 7 * 24 * time.Hour
		}
	}
	return &CacheFile{
		ctx:          ctx,
		path:         filemanager.BasePath(ctx, path),
		cacheID:      cacheIDBytes,
		storeFakeIP:  options.StoreFakeIP,
		storeRDRC:    options.StoreRDRC,
		rdrcTimeout:  rdrcTimeout,
		saveDomain:   make(map[netip.Addr]string),
		saveAddress4: make(map[string]netip.Addr),
		saveAddress6: make(map[string]netip.Addr),
		saveRDRC:     make(map[saveRDRCCacheKey]bool),
	}
}

func (c *CacheFile) Name() string {
	return "cache-file"
}

func (c *CacheFile) Dependencies() []string {
	return nil
}

func (c *CacheFile) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	const fileMode = 0o666
	options := bbolt.Options{Timeout: time.Second}
	var (
		db  *bbolt.DB
		err error
	)
	for range 10 {
		db, err = bbolt.Open(c.path, fileMode, &options)
		if err == nil {
			break
		}
		if errors.Is(err, bboltErrors.ErrTimeout) {
			continue
		}
		if E.IsMulti(err, bboltErrors.ErrInvalid, bboltErrors.ErrChecksum, bboltErrors.ErrVersionMismatch) {
			rmErr := os.Remove(c.path)
			if rmErr != nil {
				return err
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	err = filemanager.Chown(c.ctx, c.path)
	if err != nil {
		db.Close()
		return E.Cause(err, "platform chown")
	}
	err = db.Batch(func(tx *bbolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bbolt.Bucket) error {
			if name[0] == 0 {
				return b.ForEachBucket(func(k []byte) error {
					bucketName := string(k)
					if !(common.Contains(bucketNameList, bucketName)) {
						_ = b.DeleteBucket(name)
					}
					return nil
				})
			} else {
				bucketName := string(name)
				if !(common.Contains(bucketNameList, bucketName) || strings.HasPrefix(bucketName, fakeipBucketPrefix)) {
					_ = tx.DeleteBucket(name)
				}
			}
			return nil
		})
	})
	if err != nil {
		db.Close()
		return err
	}
	c.DB = db
	moved := c.moveRuleSetsToFiles()
	// the move may have reset the database (a damaged page found on the way): the one it left
	db, err = c.compactSparse(c.DB, moved)
	if err != nil {
		return err
	}
	c.DB = db
	c.pruneRuleSetFiles(db)
	return nil
}

func (c *CacheFile) Close() error {
	if c.DB == nil {
		return nil
	}
	return c.DB.Close()
}

func (c *CacheFile) view(fn func(tx *bbolt.Tx) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			c.resetDB()
			err = E.New("database corrupted: ", r)
		}
	}()
	return c.DB.View(fn)
}

func (c *CacheFile) batch(fn func(tx *bbolt.Tx) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			c.resetDB()
			err = E.New("database corrupted: ", r)
		}
	}()
	return c.DB.Batch(fn)
}

func (c *CacheFile) update(fn func(tx *bbolt.Tx) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			c.resetDB()
			err = E.New("database corrupted: ", r)
		}
	}()
	return c.DB.Update(fn)
}

func (c *CacheFile) resetDB() {
	c.resetAccess.Lock()
	defer c.resetAccess.Unlock()
	c.generation.Add(1)
	c.DB.Close()
	os.Remove(c.path)
	db, err := bbolt.Open(c.path, 0o666, &bbolt.Options{Timeout: time.Second})
	if err == nil {
		_ = filemanager.Chown(c.ctx, c.path)
		c.DB = db
	}
}

func (c *CacheFile) StoreFakeIP() bool {
	return c.storeFakeIP
}

func (c *CacheFile) LoadMode() string {
	var mode string
	c.view(func(t *bbolt.Tx) error {
		bucket := t.Bucket(bucketMode)
		if bucket == nil {
			return nil
		}
		var modeBytes []byte
		if len(c.cacheID) > 0 {
			modeBytes = bucket.Get(c.cacheID)
		} else {
			modeBytes = bucket.Get(cacheIDDefault)
		}
		mode = string(modeBytes)
		return nil
	})
	return mode
}

func (c *CacheFile) StoreMode(mode string) error {
	return c.batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketMode)
		if err != nil {
			return err
		}
		if len(c.cacheID) > 0 {
			return bucket.Put(c.cacheID, []byte(mode))
		} else {
			return bucket.Put(cacheIDDefault, []byte(mode))
		}
	})
}

func (c *CacheFile) bucket(t *bbolt.Tx, key []byte) *bbolt.Bucket {
	if c.cacheID == nil {
		return t.Bucket(key)
	}
	bucket := t.Bucket(c.cacheID)
	if bucket == nil {
		return nil
	}
	return bucket.Bucket(key)
}

func (c *CacheFile) createBucket(t *bbolt.Tx, key []byte) (*bbolt.Bucket, error) {
	if c.cacheID == nil {
		return t.CreateBucketIfNotExists(key)
	}
	bucket, err := t.CreateBucketIfNotExists(c.cacheID)
	if bucket == nil {
		return nil, err
	}
	return bucket.CreateBucketIfNotExists(key)
}

func (c *CacheFile) LoadSelected(group string) string {
	var selected string
	c.view(func(t *bbolt.Tx) error {
		bucket := c.bucket(t, bucketSelected)
		if bucket == nil {
			return nil
		}
		selectedBytes := bucket.Get([]byte(group))
		if len(selectedBytes) > 0 {
			selected = string(selectedBytes)
		}
		return nil
	})
	return selected
}

func (c *CacheFile) StoreSelected(group, selected string) error {
	return c.batch(func(t *bbolt.Tx) error {
		bucket, err := c.createBucket(t, bucketSelected)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(group), []byte(selected))
	})
}

func (c *CacheFile) LoadGroupExpand(group string) (isExpand bool, loaded bool) {
	c.view(func(t *bbolt.Tx) error {
		bucket := c.bucket(t, bucketExpand)
		if bucket == nil {
			return nil
		}
		expandBytes := bucket.Get([]byte(group))
		if len(expandBytes) == 1 {
			isExpand = expandBytes[0] == 1
			loaded = true
		}
		return nil
	})
	return
}

func (c *CacheFile) StoreGroupExpand(group string, isExpand bool) error {
	return c.batch(func(t *bbolt.Tx) error {
		bucket, err := c.createBucket(t, bucketExpand)
		if err != nil {
			return err
		}
		if isExpand {
			return bucket.Put([]byte(group), []byte{1})
		} else {
			return bucket.Put([]byte(group), []byte{0})
		}
	})
}

func (c *CacheFile) LoadRuleSet(tag string) *adapter.SavedBinary {
	if saved, found := c.loadRuleSetFile(tag); found {
		return saved
	}
	var savedSet adapter.SavedBinary
	err := c.view(func(t *bbolt.Tx) error {
		bucket := c.bucket(t, bucketRuleSet)
		if bucket == nil {
			return os.ErrNotExist
		}
		setBinary := bucket.Get([]byte(tag))
		if len(setBinary) == 0 {
			return os.ErrInvalid
		}
		return savedSet.UnmarshalBinary(setBinary)
	})
	if err != nil {
		return nil
	}
	return &savedSet
}

var _ adapter.RuleSetCheckCache = (*CacheFile)(nil)

// LoadRuleSetChecked is when the rule set was last found up to date, the zero time when
// that is not kept.
func (c *CacheFile) LoadRuleSetChecked(tag string) time.Time {
	var at time.Time
	_ = c.view(func(t *bbolt.Tx) error {
		bucket := c.bucket(t, bucketRuleSetChecked)
		if bucket == nil {
			return nil
		}
		if value := bucket.Get([]byte(tag)); len(value) == 8 {
			at = time.Unix(0, int64(binary.BigEndian.Uint64(value)))
		}
		return nil
	})
	return at
}

// StoreRuleSetChecked keeps when the rule set was found up to date: eight bytes, where a
// save of the rule set writes its whole content again.
func (c *CacheFile) StoreRuleSetChecked(tag string, at time.Time) error {
	return c.batch(func(t *bbolt.Tx) error {
		bucket, err := c.createBucket(t, bucketRuleSetChecked)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(tag), binary.BigEndian.AppendUint64(nil, uint64(at.UnixNano())))
	})
}

// SaveRuleSet keeps the content of a rule set in a file of its own (rule_set_file.go).
func (c *CacheFile) SaveRuleSet(tag string, set *adapter.SavedBinary) error {
	return c.saveRuleSetFile(tag, set)
}

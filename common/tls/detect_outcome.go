//go:build with_utls

package tls

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

// detectOutcomeWriter keeps in the cache file what the block detector reads of one server
// (podkop-engine). It is shared by a client configuration and its clones. The cache file is on
// flash by default, so a handshake that changes nothing writes nothing: there is no write by
// time, and a restart begins with what the file holds. The writes are made in the order of the
// changes by one goroutine at most, which takes the latest state when several came meanwhile.
//
// A state that changes with every connection (a path that lets some handshakes through and not
// the others, a server that answers by turns as itself and as a stranger) would be a commit of
// the cache file for every connection. So the changes of one server are written
// detectOutcomeWriteBurst at once, then one in detectOutcomeWriteEvery, the latest state: what
// the file tells of the server is behind by that time at most, and only while its state changes
// that often.
type detectOutcomeWriter struct {
	access sync.Mutex
	// set once, by open: the box registers the cache file after it has made the outbounds
	cache adapter.CacheFile
	key   string
	// the state, and the time it took effect
	flags       byte
	fingerprint string
	at          time.Time
	// the state was read from the file and no handshake of this process has confirmed it
	seeded bool
	// a change is waiting for the goroutine; the goroutine runs
	dirty   bool
	writing bool
	// the writes that may go at once, and the time the last of them was counted back
	allowance int
	allowedAt time.Time
	// handshakes in a row that met their deadline, with the fallback off
	deadlines atomic.Int32
}

// The bound of the writes of one server's state (variables for the tests).
var (
	// detectOutcomeWriteBurst is how many changes are written at once. What happens to a server
	// is two changes (it stops answering, then a fingerprint gets through) or three (it refuses
	// as well); two paths that settle on candidates of their own make four
	// (TestDetectOutcomeWritesOnChange).
	detectOutcomeWriteBurst = 4
	// detectOutcomeWriteEvery is the time that gives one write back: as long as a line of the
	// fallback's log takes to be written again (utlsFallbackLogInterval), for the same reason, a
	// path that gives the same on every connection. 8640 commits a day at most, where every
	// connection made one.
	detectOutcomeWriteEvery = 10 * time.Second
)

// open gives the writer its place in the cache file, once.
func (w *detectOutcomeWriter) open(cache adapter.CacheFile, key string) {
	w.access.Lock()
	defer w.access.Unlock()
	if w.cache != nil {
		return
	}
	w.cache, w.key = cache, key
	w.allowance, w.allowedAt = detectOutcomeWriteBurst, time.Now()
	flags, fingerprint, at, loaded := cache.LoadDetectOutcome(key)
	if loaded {
		w.flags, w.fingerprint, w.at, w.seeded = flags, fingerprint, at, true
	}
}

// answered records a completed handshake: change makes the state of it from the one known.
func (w *detectOutcomeWriter) answered(now time.Time, change func(flags byte, fingerprint string) (byte, string)) {
	w.access.Lock()
	defer w.access.Unlock()
	if w.cache == nil {
		return
	}
	flags, fingerprint := change(w.flags, w.fingerprint)
	w.commit(now, flags, fingerprint, false)
}

// failed records that no handshake was completed, for the reason in flag (DetectNoAnswer,
// DetectFailed). DetectRefused is a fact of the server and stays. The time of a failure says how
// fresh it is, and one of an earlier run says nothing of this one, so the first failure of a
// process is written even when it is the same as the state read from the file.
func (w *detectOutcomeWriter) failed(now time.Time, flag byte) {
	w.access.Lock()
	defer w.access.Unlock()
	if w.cache == nil {
		return
	}
	w.commit(now, w.flags&adapter.DetectRefused|flag, "", w.seeded)
}

// commit takes the state and has it written if it changed. The caller holds the lock.
func (w *detectOutcomeWriter) commit(now time.Time, flags byte, fingerprint string, force bool) {
	w.seeded = false
	if !force && flags == w.flags && fingerprint == w.fingerprint {
		return
	}
	w.flags, w.fingerprint, w.at = flags, fingerprint, now
	w.dirty = true
	if !w.writing {
		w.writing = true
		go w.write()
	}
}

func (w *detectOutcomeWriter) write() {
	for {
		w.access.Lock()
		if !w.dirty {
			w.writing = false
			w.access.Unlock()
			return
		}
		if wait := w.allow(time.Now()); wait > 0 {
			// the state may change again meanwhile: the one of that moment is written
			w.access.Unlock()
			time.Sleep(wait)
			continue
		}
		w.dirty = false
		flags, fingerprint, at := w.flags, w.fingerprint, w.at
		w.access.Unlock()
		_ = w.cache.StoreDetectOutcome(w.key, flags, fingerprint, at)
	}
}

// allow takes one write of the allowance at now and returns 0, or tells how long until there is
// one. The caller holds the lock.
func (w *detectOutcomeWriter) allow(now time.Time) time.Duration {
	every, burst := detectOutcomeWriteEvery, detectOutcomeWriteBurst
	if every <= 0 || burst <= 0 {
		return 0
	}
	if back := now.Sub(w.allowedAt) / every; back > 0 {
		if w.allowance+int(min(back, time.Duration(burst))) >= burst {
			w.allowance, w.allowedAt = burst, now
		} else {
			w.allowance += int(back)
			w.allowedAt = w.allowedAt.Add(back * every)
		}
	}
	if w.allowance > 0 {
		if w.allowance == burst {
			// the time that gives a write back runs from the first one taken
			w.allowedAt = now
		}
		w.allowance--
		return 0
	}
	return w.allowedAt.Add(every).Sub(now)
}

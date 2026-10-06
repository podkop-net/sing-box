package fakeip

import (
	"cmp"
	"context"
	"encoding/binary"
	"math"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

var _ adapter.FakeIPStore = (*Store)(nil)

const (
	firstOffset = 2     // as before: the network address and the one after it are not given out
	reserveStep = 1024  // addresses the saved allocation position runs ahead of the one in memory
	recordLimit = 65536 // records of one range, whatever its size
	// the unit of the time of last use: 32 bits last for 13 years of uptime
	tickUnit = 100 * time.Millisecond

	// a record that neither a query nor a new connection used for this long is removed
	idleTimeout = 24 * time.Hour
	// a record used within this time is not removed to keep the number of records down,
	// and the addresses that may not have been saved before a kill are held back for it
	protectTime = time.Hour
	// how often unused records are looked for
	sweepInterval = time.Minute
	// the pause before a save is tried again after one failed
	saveRetry = time.Second
)

// tableStorage keeps a plain table of addresses and domains for a store that answers from
// memory (the cache file): it is read once at start and then receives the changes.
type tableStorage interface {
	// FakeIPLoadTable passes every saved record to load and removes the ones load
	// refuses. It returns the saved allocation position, if there is one, and whether
	// it was saved by a clean stop. What was read stays valid when err is set.
	FakeIPLoadTable(load func(address netip.Addr, domain string) bool) (metadata *adapter.FakeIPMetadata, clean bool, err error)
	// FakeIPSaveChanges writes records, removes others and saves the allocation position
	// in one transaction. clean: the store stops, the position is exact and is also
	// written where older versions read it.
	FakeIPSaveChanges(puts map[netip.Addr]string, deletes []netip.Addr, metadata *adapter.FakeIPMetadata, clean bool) error
	// FakeIPGeneration changes when the storage lost its content (a damaged cache file
	// is recreated).
	FakeIPGeneration() uint64
	FakeIPReset() error
}

type record struct {
	domain string // empty: the address is held back, see pool.hold
	offset uint32
	// the last query for the domain or connection to the address: Store.now in the upper
	// half, the number of the use in the lower half, see Store.stamp
	lastUse  atomic.Uint64
	dirty    bool // not in the storage yet
	removing bool // being removed from the storage
}

func (r *record) held() bool {
	return r.domain == ""
}

// useTick returns the time of a use.
func useTick(lastUse uint64) uint32 {
	return uint32(lastUse >> 32)
}

// since returns the ticks from a use to now. A use later than now counts as now: the
// clock was read before the use.
func since(now uint32, lastUse uint64) uint32 {
	if tick := useTick(lastUse); tick < now {
		return now - tick
	}
	return 0
}

// removal is a record chosen to be removed, valid while the record is not used again.
type removal struct {
	pool    *pool
	record  *record
	lastUse uint64
}

// pool is one address range. The addresses given out are the offsets [first, end) from
// the network address, taken in a ring.
type pool struct {
	prefix   netip.Prefix
	base     netip.Addr
	first    uint32
	end      uint32
	byName   map[string]*record
	byOffset map[uint32]*record
	next     uint32 // tried first for a new domain
	advanced uint64 // offsets next has moved over

	// with a storage: next may move over budget more offsets, then a new reserve has to
	// be saved; reserveLast is the last offset of the saved reserve
	step        uint32
	budget      uint32
	reserved    bool
	reserveLast uint32
	dirty       []*record
	expired     []removal
	// offsets of records that left the memory while the storage could not be written:
	// the storage still has them, the next save removes them there
	forgotten []uint32

	limit      int    // records kept when there is a choice: more go, the ones unused longest first
	max        uint32 // records at most: a new domain then takes the place of the ones unused longest
	fullWarned time.Time
}

func newPool(prefix netip.Prefix) *pool {
	prefix = prefix.Masked()
	p := &pool{
		prefix:   prefix,
		base:     prefix.Addr(),
		first:    firstOffset,
		end:      math.MaxUint32, // the start of a range wider than that
		byName:   make(map[string]*record),
		byOffset: make(map[uint32]*record),
		next:     firstOffset,
	}
	if hostBits := prefix.Addr().BitLen() - prefix.Bits(); hostBits < 32 {
		p.end = uint32(1)<<hostBits - 1 // the broadcast address is not given out
	}
	usable := p.usable()
	if usable == 0 {
		return p
	}
	p.step = min(reserveStep, max(usable/4, 1))
	// a quarter of the range, a small range whole
	p.limit = int(min(max(usable/4, min(usable, 256)), recordLimit))
	p.max = usable
	if uint64(p.limit)*2 < uint64(usable) {
		p.max = uint32(p.limit) * 2
	}
	return p
}

func (p *pool) usable() uint32 {
	if p.end <= p.first {
		return 0
	}
	return p.end - p.first
}

func (p *pool) full() bool {
	return uint32(len(p.byOffset)) >= p.max
}

// room returns how many records make room for new domains when the range is full.
func (p *pool) room() uint32 {
	return max(uint32(len(p.byOffset))/16, 1)
}

func (p *pool) address(offset uint32) netip.Addr {
	if p.base.Is4() {
		raw := p.base.As4()
		binary.BigEndian.PutUint32(raw[:], binary.BigEndian.Uint32(raw[:])+offset)
		return netip.AddrFrom4(raw)
	}
	raw := p.base.As16()
	binary.BigEndian.PutUint64(raw[8:], binary.BigEndian.Uint64(raw[8:])+uint64(offset))
	return netip.AddrFrom16(raw)
}

// offset returns the place of address in the range, false if it is not in the part of the
// range the offsets cover.
func (p *pool) offset(address netip.Addr) (uint32, bool) {
	if !p.prefix.Contains(address) {
		return 0, false
	}
	var offset uint64
	if p.base.Is4() {
		raw, base := address.As4(), p.base.As4()
		offset = uint64(binary.BigEndian.Uint32(raw[:]) - binary.BigEndian.Uint32(base[:]))
	} else {
		raw, base := address.As16(), p.base.As16()
		if binary.BigEndian.Uint64(raw[:8]) != binary.BigEndian.Uint64(base[:8]) {
			return 0, false
		}
		offset = binary.BigEndian.Uint64(raw[8:]) - binary.BigEndian.Uint64(base[8:])
	}
	if offset >= uint64(p.end) {
		return 0, false
	}
	return uint32(offset), true
}

// after returns the offset that follows offset in the ring.
func (p *pool) after(offset uint32) uint32 {
	if offset < p.first || offset >= p.end-1 {
		return p.first
	}
	return offset + 1
}

// ahead returns the offset count steps after offset in the ring.
func (p *pool) ahead(offset uint32, count uint32) uint32 {
	return p.first + uint32((uint64(offset-p.first)+uint64(count))%uint64(p.usable()))
}

func (p *pool) remove(r *record) {
	delete(p.byOffset, r.offset)
	if !r.held() && p.byName[r.domain] == r {
		delete(p.byName, r.domain)
	}
}

// restore sets the allocation position and the index of domains once the saved records
// are read. current is the saved position, the last address that may have been given out;
// restore returns its offset and whether there is one. The records get the time of use
// tick, in the order they were given out.
func (p *pool) restore(current netip.Addr, tick uint32) (uint32, bool) {
	p.next = p.first
	var (
		last       uint32
		positioned bool
	)
	if current.IsValid() {
		last, positioned = p.offset(current)
		if positioned {
			p.next = p.after(last)
		}
	}
	if !positioned && len(p.byOffset) > 0 {
		// no position was saved (a version that lost it wrote the file): after the last
		// address in use
		var highest uint32
		for offset := range p.byOffset {
			highest = max(highest, offset)
		}
		p.next = p.after(highest)
	}
	usable := uint64(p.usable())
	age := func(r *record) uint64 { // how many addresses ago this one was given out
		return (uint64(p.next-p.first) + usable - 1 - uint64(r.offset-p.first)) % usable
	}
	for _, r := range p.byOffset {
		r.lastUse.Store(uint64(tick)<<32 | uint64(uint32(usable-1-age(r))))
		// a domain saved with two addresses (versions that told its spellings apart, or
		// that gave a known domain a new address): both lead to it, the later one is
		// given out
		other := p.byName[r.domain]
		if other == nil || age(r) < age(other) {
			p.byName[r.domain] = r
		}
	}
	return last, positioned
}

// hold keeps the free addresses of the saved reserve, which ends at last, from being given
// out: after a stop without a save some of them were given out and not saved, and clients
// may hold them. They are held as records without a domain, released as unused ones are.
func (p *pool) hold(last uint32, lastUse uint64) {
	if last < p.first {
		return
	}
	usable := p.usable()
	for back := range p.step {
		offset := p.ahead(last, usable-back)
		if p.byOffset[offset] == nil {
			r := &record{offset: offset}
			r.lastUse.Store(lastUse)
			p.byOffset[offset] = r
		}
	}
}

// oldest returns up to count records unused longest, among those not used within protect
// ticks. Addresses held back are given up only when nothing else can make room.
func (p *pool) oldest(count uint32, protect uint32, tick uint32) []removal {
	candidates := make([]removal, 0, len(p.byOffset))
	var heldBack []removal
	for _, r := range p.byOffset {
		lastUse := r.lastUse.Load()
		switch {
		case r.removing:
		case r.held():
			heldBack = append(heldBack, removal{p, r, lastUse})
		case since(tick, lastUse) >= protect:
			candidates = append(candidates, removal{p, r, lastUse})
		}
	}
	if len(candidates) == 0 && protect == 0 {
		candidates = heldBack
	}
	slices.SortFunc(candidates, func(a, b removal) int {
		return cmp.Compare(a.lastUse, b.lastUse)
	})
	if uint32(len(candidates)) > count {
		candidates = candidates[:count]
	}
	return candidates
}

// Store gives out FakeIP addresses and keeps the whole map in memory: every query and
// every connection is answered from it. A storage that keeps a table (the cache file) is
// read once at start and then only receives the changes, in the background, so an answer
// never waits for a write.
//
// What keeps an address from reaching a second domain while a client may still hold it:
//   - a new domain takes the next free address of the ring, addresses in use are stepped
//     over, whatever the saved position says;
//   - the position is saved ahead of the addresses given out (a reserve); after a stop
//     without a save (a crash, a kill) allocation goes on behind the reserve, and the
//     addresses given out but not saved yet have no record: connections to them are
//     refused ("missing fakeip record") instead of reaching another domain. The free
//     addresses of that reserve are held back for protectTime;
//   - a record leaves memory only after it left the storage, so a crash cannot bring an
//     old domain back to an address that was given out again;
//   - a record is removed when neither a query nor a new connection used it for
//     idleTimeout, or to keep the number of records down, the ones unused longest first.
//
// While the storage cannot be written (no space left, a file system turned read-only, a
// cache file that could not be reopened) the store goes on from memory: new domains get
// addresses past the saved reserve, and a full range makes room without the storage. The
// first write that succeeds saves all of it and a new reserve. A crash or a kill during
// such a time is not covered by the above: an address given out past the reserve has no
// record and can be given to another domain, and an address that made room can lead to its
// previous domain. That is what any address could do before the reserve existed, and a
// query without an answer for as long as the file cannot be written is worse.
type Store struct {
	ctx        context.Context
	logger     logger.Logger
	inet4Range netip.Prefix
	inet6Range netip.Prefix
	pool4      *pool
	pool6      *pool

	// time of use: ticks of the monotonic clock since start, see now
	tick         atomic.Uint32 // the clock of tests
	uses         atomic.Uint32 // numbers the uses: which of two records was used later
	startTick    uint32
	idleTicks    uint32
	protectTicks uint32
	started      time.Time

	sweepInterval time.Duration
	saveRetry     time.Duration

	access sync.RWMutex // the pools
	closed bool

	storage    tableStorage // nil: nothing is saved
	saveAccess sync.Mutex   // one write to the storage at a time
	generation uint64
	// the last write to the storage failed: queries do not wait for it, see allocate
	storageFailed bool

	wake     chan struct{}
	done     chan struct{}
	loopDone chan struct{}

	testStorage tableStorage
	manual      bool                     // tests move the clock and call sweep and save themselves
	removed     func(p *pool, r *record) // tests: a record is removed by the rules of the store
}

func NewStore(ctx context.Context, logger logger.Logger, inet4Range netip.Prefix, inet6Range netip.Prefix) *Store {
	store := &Store{
		ctx:           ctx,
		logger:        logger,
		inet4Range:    inet4Range,
		inet6Range:    inet6Range,
		idleTicks:     uint32(idleTimeout / tickUnit),
		protectTicks:  uint32(protectTime / tickUnit),
		sweepInterval: sweepInterval,
		saveRetry:     saveRetry,
		wake:          make(chan struct{}, 1),
	}
	// not zero, so that records read at start can be given a time of use in the past
	store.startTick = store.idleTicks + 2
	store.tick.Store(store.startTick)
	if inet4Range.IsValid() {
		store.pool4 = newPool(inet4Range)
	}
	if inet6Range.IsValid() {
		store.pool6 = newPool(inet6Range)
	}
	return store
}

func (s *Store) pools() []*pool {
	pools := make([]*pool, 0, 2)
	if s.pool4 != nil {
		pools = append(pools, s.pool4)
	}
	if s.pool6 != nil {
		pools = append(pools, s.pool6)
	}
	return pools
}

func (s *Store) poolOf(address netip.Addr) *pool {
	if s.pool4 != nil && s.pool4.prefix.Contains(address) {
		return s.pool4
	}
	if s.pool6 != nil && s.pool6.prefix.Contains(address) {
		return s.pool6
	}
	return nil
}

func (s *Store) Start() error {
	for _, p := range s.pools() {
		if p.usable() == 0 {
			return E.New("fakeip: range ", p.prefix.String(), " has no address to give out")
		}
	}
	storage := s.testStorage
	if storage == nil {
		cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
		if cacheFile != nil && cacheFile.StoreFakeIP() {
			table, isTable := cacheFile.(tableStorage)
			if isTable {
				storage = table
			} else {
				s.logger.Warn("fakeip: the cache file cannot keep the address table, addresses are not saved")
			}
		}
	}
	s.started = time.Now()
	if storage != nil {
		s.load(storage)
	}
	if !s.manual {
		s.done = make(chan struct{})
		s.loopDone = make(chan struct{})
		go s.loop()
	}
	return nil
}

func (s *Store) load(storage tableStorage) {
	s.storage = storage
	// before the table is read: a cache file recreated meanwhile gets the table again
	s.generation = storage.FakeIPGeneration()
	metadata, clean, err := storage.FakeIPLoadTable(func(address netip.Addr, domain string) bool {
		p := s.poolOf(address)
		if p == nil || domain == "" {
			return false
		}
		offset, inRange := p.offset(address)
		if !inRange || offset < p.first {
			return false
		}
		p.byOffset[offset] = &record{domain: strings.ToLower(domain), offset: offset}
		return true
	})
	if err != nil {
		// what was read is kept: the addresses are in the file and clients hold them
		s.logger.Error("fakeip: read the saved addresses: ", err)
	}
	var count int
	for _, p := range s.pools() {
		var current netip.Addr
		if metadata != nil {
			if p == s.pool6 && metadata.Inet6Range == s.inet6Range {
				current = metadata.Inet6Current
			} else if p == s.pool4 && metadata.Inet4Range == s.inet4Range {
				current = metadata.Inet4Current
			}
		}
		// used a moment before the start, as far as this process can tell: after a
		// restart no record is released or gives way before it is unused for the usual
		// time
		last, positioned := p.restore(current, s.startTick-1)
		count += len(p.byOffset)
		if positioned && !clean && s.protectTicks > 0 {
			// they turn unused protectTime after the start
			p.hold(last, uint64(s.startTick-1-(s.idleTicks-s.protectTicks))<<32)
		}
	}
	// the reserve goes to the storage before anything is given out; when it cannot be
	// written, the store goes on from memory as it does whenever the storage fails
	err = s.save(saveRequest{})
	if err != nil {
		s.logger.Error("fakeip: save the allocation position: ", err)
	}
	s.logger.Info("fakeip: ", count, " addresses read from the cache file")
}

func (s *Store) Contains(address netip.Addr) bool {
	return s.inet4Range.Contains(address) || s.inet6Range.Contains(address)
}

func (s *Store) Close() error {
	s.access.Lock()
	if s.closed {
		s.access.Unlock()
		return nil
	}
	s.closed = true
	if s.loopDone != nil {
		// before closed can be seen: a save of the loop that is refused because of it
		// finds the loop told to stop, and does not log the refusal as a failed save
		close(s.done)
	}
	s.access.Unlock()
	if s.loopDone != nil {
		<-s.loopDone
	}
	err := s.save(saveRequest{clean: true})
	if err != nil {
		s.logger.Error("fakeip: save addresses on stop: ", err)
	}
	return err
}

// release removes a record that is unused or has to make room.
func (s *Store) release(p *pool, r *record) {
	p.remove(r)
	if s.removed != nil {
		s.removed(p, r)
	}
}

// now is the time for record.lastUse.
func (s *Store) now() uint32 {
	if s.manual {
		return s.tick.Load()
	}
	return s.startTick + uint32(time.Since(s.started)/tickUnit)
}

// stamp is the value of record.lastUse for a use now. The number of the use orders the
// records used within one tick: which one is unused longest must not be a matter of chance
// when a small range is used up within a tick.
func (s *Store) stamp() uint64 {
	return uint64(s.now())<<32 | uint64(s.uses.Add(1))
}

func (s *Store) touch(r *record) {
	r.lastUse.Store(s.stamp())
}

func (s *Store) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Store) Create(domain string, isIPv6 bool) (netip.Addr, error) {
	p := s.pool4
	if isIPv6 {
		p = s.pool6
	}
	if p == nil {
		if isIPv6 {
			return netip.Addr{}, E.New("missing IPv6 fakeip address range")
		}
		return netip.Addr{}, E.New("missing IPv4 fakeip address range")
	}
	// one record for all spellings of a name (RFC 4343)
	domain = strings.ToLower(domain)
	s.access.RLock()
	r := p.byName[domain]
	if r != nil {
		s.touch(r)
	}
	s.access.RUnlock()
	if r != nil {
		return p.address(r.offset), nil
	}
	for {
		address, need, err := s.allocate(p, domain)
		// A save that fails does not fail the query: once the storage is known to fail,
		// allocate goes on from memory, and it is allocate that refuses a closed store.
		switch need {
		case needReserve:
			_ = s.save(saveRequest{reserve: true})
		case needRoom:
			s.makeRoom(p)
		default:
			return address, err
		}
	}
}

const (
	needNothing = iota
	needReserve // the saved reserve is used up
	needRoom    // the range holds as many records as it may
)

func (s *Store) allocate(p *pool, domain string) (netip.Addr, int, error) {
	s.access.Lock()
	defer s.access.Unlock()
	if r := p.byName[domain]; r != nil {
		s.touch(r)
		return p.address(r.offset), needNothing, nil
	}
	if s.closed {
		return netip.Addr{}, needNothing, E.New("fakeip store closed")
	}
	if p.full() {
		return netip.Addr{}, needRoom, nil
	}
	saved := s.storage != nil
	if saved && s.storage.FakeIPGeneration() != s.generation {
		// the cache file was recreated: nothing is given out until it has the table and
		// the reserve again
		return netip.Addr{}, needReserve, nil
	}
	for {
		// while the storage fails there is no reserve to wait for: what is left of the
		// saved one is used up, then addresses are given out past it
		if saved && p.budget == 0 && !s.storageFailed {
			return netip.Addr{}, needReserve, nil
		}
		offset := p.next
		p.next = p.after(offset)
		p.advanced++
		if saved && p.budget > 0 {
			p.budget--
		}
		if p.byOffset[offset] != nil {
			continue
		}
		r := &record{domain: domain, offset: offset, dirty: saved}
		r.lastUse.Store(s.stamp())
		p.byName[domain] = r
		p.byOffset[offset] = r
		if saved {
			p.dirty = append(p.dirty, r)
			s.signal()
		}
		return p.address(offset), needNothing, nil
	}
}

// makeRoom is called when a new domain finds the range full: the records unused longest
// go, whatever their age. They go even when the storage cannot be written, see save.
func (s *Store) makeRoom(p *pool) {
	s.access.Lock()
	if time.Since(p.fullWarned) > time.Minute {
		p.fullWarned = time.Now()
		s.logger.Warn("fakeip: no free address in ", p.prefix.String(), ", releasing the ones unused longest")
	}
	if s.storage == nil {
		if p.full() {
			for _, candidate := range p.oldest(p.room(), 0, s.now()) {
				s.release(p, candidate.record)
			}
		}
		s.access.Unlock()
		return
	}
	s.access.Unlock()
	_ = s.save(saveRequest{room: p})
}

func (s *Store) Lookup(address netip.Addr) (string, bool) {
	p := s.poolOf(address)
	if p == nil {
		return "", false
	}
	offset, inRange := p.offset(address)
	if !inRange {
		return "", false
	}
	s.access.RLock()
	defer s.access.RUnlock()
	r := p.byOffset[offset]
	if r == nil || r.held() {
		return "", false
	}
	s.touch(r)
	return r.domain, true
}

// Reset forgets every address. The allocation position stays: clients may still hold the
// addresses given out so far.
func (s *Store) Reset() error {
	s.saveAccess.Lock()
	defer s.saveAccess.Unlock()
	if s.storage != nil {
		// first: if it fails, the memory still agrees with the storage
		err := s.storage.FakeIPReset()
		if err != nil {
			return err
		}
	}
	s.access.Lock()
	defer s.access.Unlock()
	for _, p := range s.pools() {
		clear(p.byName)
		clear(p.byOffset)
		p.dirty = nil
		p.expired = nil
		p.forgotten = nil
	}
	return nil
}

type saveRequest struct {
	clean bool // the store stops: the exact position, also where older versions read it
	// from a query that cannot go on: it found the reserve of a range used up, or this
	// range full (the records unused longest go). If another query has seen to it
	// meanwhile, nothing is written: the pending changes wait for the loop.
	reserve bool
	room    *pool
}

// save writes the pending changes to the storage and extends the reserve of the
// allocation position when it is half used. The pools are not locked during the write.
func (s *Store) save(request saveRequest) error {
	s.saveAccess.Lock()
	defer s.saveAccess.Unlock()
	storage := s.storage
	if storage == nil {
		return nil
	}
	generation := storage.FakeIPGeneration()

	s.access.Lock()
	if s.closed && !request.clean {
		s.access.Unlock()
		return E.New("fakeip store closed")
	}
	pools := s.pools()
	if generation != s.generation {
		// the cache file was damaged and is recreated: the table and the reserve go there
		// again
		s.generation = generation
		var count int
		for _, p := range pools {
			p.reserved = false
			p.budget = 0
			p.forgotten = nil
			p.dirty = p.dirty[:0]
			for _, r := range p.byOffset {
				if r.held() {
					continue
				}
				r.dirty = true
				p.dirty = append(p.dirty, r)
			}
			count += len(p.dirty)
		}
		s.logger.Warn("fakeip: the cache file was recreated, saving ", count, " addresses again")
	}
	if request.reserve || request.room != nil {
		needed := request.room != nil && request.room.full()
		for _, p := range pools {
			needed = needed || !p.reserved || p.budget == 0
		}
		if !needed {
			s.access.Unlock()
			return nil
		}
	}
	type reservation struct {
		pool     *pool
		advanced uint64
		last     uint32
	}
	var (
		puts     = make(map[netip.Addr]string)
		written  []removal // records written by this save, with their pools
		deletes  []netip.Addr
		removals []removal
		reserves []reservation
		changed  = request.clean
		metadata = &adapter.FakeIPMetadata{Inet4Range: s.inet4Range, Inet6Range: s.inet6Range}
	)
	for _, p := range pools {
		if request.room == p && p.full() {
			p.expired = append(p.expired, p.oldest(p.room(), 0, s.now())...)
		}
		// not on a stop: a record used while its removal is written is saved again by the
		// next save, and there is none
		for _, candidate := range p.expired {
			r := candidate.record
			if request.clean || r.removing || p.byOffset[r.offset] != r || r.lastUse.Load() != candidate.lastUse {
				continue // chosen twice, gone, or used since it was chosen
			}
			r.removing = true
			deletes = append(deletes, p.address(r.offset))
			removals = append(removals, candidate)
		}
		p.expired = nil
		for _, offset := range p.forgotten {
			// an address that was given out again is written with its new domain
			if p.byOffset[offset] == nil {
				deletes = append(deletes, p.address(offset))
			}
		}
		var later []*record
		for _, r := range p.dirty {
			if !r.dirty || p.byOffset[r.offset] != r {
				continue
			}
			if r.removing {
				later = append(later, r)
				continue
			}
			puts[p.address(r.offset)] = r.domain
			written = append(written, removal{pool: p, record: r})
		}
		p.dirty = later

		var last uint32
		switch {
		case request.clean && p.next == p.first:
			// as a range that gave out nothing has it in every version
			last = p.first - 1
		case request.clean:
			// the address before the position: nothing is stepped over after a clean stop
			last = p.ahead(p.next, p.usable()-1)
		case !p.reserved || p.budget == 0 || p.budget < p.step/2:
			last = p.ahead(p.next, p.step-1)
			reserves = append(reserves, reservation{p, p.advanced, last})
			changed = true
		default:
			last = p.reserveLast
		}
		if p == s.pool6 {
			metadata.Inet6Current = p.address(last)
		} else {
			metadata.Inet4Current = p.address(last)
		}
	}
	s.access.Unlock()

	if len(puts) == 0 && len(deletes) == 0 && !changed {
		return nil
	}
	err := storage.FakeIPSaveChanges(puts, deletes, metadata, request.clean)

	s.access.Lock()
	defer s.access.Unlock()
	if err != nil {
		s.storageFailed = true
		// the changes stay for the next attempt; the records to remove are found again
		for _, change := range written {
			change.pool.dirty = append(change.pool.dirty, change.record)
		}
		for _, candidate := range removals {
			candidate.record.removing = false
		}
		if request.room != nil && request.room.full() {
			// The query that found the range full gets its address all the same: the
			// records chosen to go leave the memory now, and the storage with the next
			// write that succeeds.
			for _, candidate := range removals {
				p, r := candidate.pool, candidate.record
				if p != request.room || p.byOffset[r.offset] != r || r.lastUse.Load() != candidate.lastUse {
					continue
				}
				s.release(p, r)
				if !r.dirty {
					p.forgotten = append(p.forgotten, r.offset)
				}
			}
		}
		return err
	}
	s.storageFailed = false
	for _, change := range written {
		change.record.dirty = false
	}
	for _, p := range pools {
		p.forgotten = nil
	}
	var removed int
	for _, candidate := range removals {
		p, r := candidate.pool, candidate.record
		r.removing = false
		if p.byOffset[r.offset] != r {
			continue
		}
		if r.lastUse.Load() != candidate.lastUse {
			// used while it was being removed: it stays and goes to the storage again
			if !r.dirty {
				r.dirty = true
				p.dirty = append(p.dirty, r)
			}
			continue
		}
		s.release(p, r)
		removed++
	}
	for _, saved := range reserves {
		p := saved.pool
		p.reserved = true
		p.reserveLast = saved.last
		// what was given out while the reserve was written; more than the reserve when
		// the storage was failing until this write: what lies past it then is covered
		// by the next save, which a budget of zero asks for at once
		p.budget = p.step - uint32(min(p.advanced-saved.advanced, uint64(p.step)))
	}
	if removed > 0 {
		var left int
		for _, p := range pools {
			left += len(p.byOffset)
		}
		s.logger.Info("fakeip: ", removed, " unused addresses released, ", left, " in use")
	}
	return nil
}

// sweep looks for records to remove: the ones unused for idleTimeout and, in a range that
// holds more than its limit, the ones unused longest among those not used within
// protectTime. With a storage they are removed by the next save.
func (s *Store) sweep() {
	tick := s.now()
	s.access.RLock()
	var found []removal
	for _, p := range s.pools() {
		var expired []removal
		for _, r := range p.byOffset {
			lastUse := r.lastUse.Load()
			if !r.removing && since(tick, lastUse) >= s.idleTicks {
				expired = append(expired, removal{p, r, lastUse})
			}
		}
		if len(p.byOffset)-len(expired) > p.limit {
			// down to 7/8 of the limit, not to repeat this for every new record
			expired = p.oldest(uint32(len(p.byOffset)-(p.limit-p.limit/8)), s.protectTicks, tick)
		}
		found = append(found, expired...)
	}
	s.access.RUnlock()
	if len(found) == 0 {
		return
	}
	s.access.Lock()
	defer s.access.Unlock()
	if s.storage != nil {
		for _, candidate := range found {
			candidate.pool.expired = append(candidate.pool.expired, candidate)
		}
		return
	}
	var removed int
	for _, candidate := range found {
		p, r := candidate.pool, candidate.record
		if p.byOffset[r.offset] == r && r.lastUse.Load() == candidate.lastUse {
			s.release(p, r)
			removed++
		}
	}
	if removed > 0 {
		s.logger.Info("fakeip: ", removed, " unused addresses released")
	}
}

// savePending tells whether there is something to save.
func (s *Store) savePending() bool {
	s.access.RLock()
	defer s.access.RUnlock()
	if s.storage.FakeIPGeneration() != s.generation {
		return true
	}
	for _, p := range s.pools() {
		if len(p.dirty) > 0 || len(p.expired) > 0 || len(p.forgotten) > 0 || !p.reserved || p.budget < p.step/2 {
			return true
		}
	}
	return false
}

// loop saves the changes as they come and looks for unused records. There is no pause
// between saves: what arrives while one save is written goes with the next one, so a burst
// of new names is a few transactions, not one per name, and a kill loses the names of the
// last moments only.
func (s *Store) loop() {
	defer close(s.loopDone)
	sweepTicker := time.NewTicker(s.sweepInterval)
	defer sweepTicker.Stop()
	var (
		retry      <-chan time.Time
		saveFailed bool
	)
	for {
		select {
		case <-s.done:
			return
		case <-s.wake:
		case <-retry:
			retry = nil
		case <-sweepTicker.C:
			s.sweep()
		}
		if s.storage == nil || retry != nil {
			continue
		}
		for s.savePending() {
			err := s.save(saveRequest{})
			if err != nil {
				select {
				case <-s.done: // the store is closing: Close saves
					return
				default:
				}
				if !saveFailed {
					s.logger.Error("fakeip: save addresses: ", err, " (new addresses are kept in memory until the cache file can be written)")
				}
				saveFailed = true
				retry = time.After(s.saveRetry)
				break
			}
			if saveFailed {
				s.logger.Info("fakeip: addresses are saved again")
				saveFailed = false
			}
			select {
			case <-s.done:
				return
			default:
			}
		}
	}
}

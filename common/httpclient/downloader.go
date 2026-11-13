package httpclient

import (
	"cmp"
	"context"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

var (
	_ adapter.HTTPDownloaders = (*Manager)(nil)
	_ adapter.HTTPDownloader  = (*Downloader)(nil)
)

// DownloadPlan is when a download starts its next way beside those under way: when none of them
// showed progress for Wait (no answer yet), or a body has paused for Body (LargeBody once Large
// bytes of it came); at most Most ways at once.
type DownloadPlan struct {
	Wait      time.Duration
	Body      time.Duration
	LargeBody time.Duration
	Large     int64
	Most      int
}

// downloadPlan is the plan of every downloader, from the delays of real ways (1200 tries a client
// on a Filogic 820, an MT7621 and an x86 server: five list sources directly and through REALITY
// with and without Vision, Trojan, Shadowsocks 2022 and hysteria2 servers near and far):
//   - Wait 4 s: the slowest answer of a way that worked, its headers after 3.78 s (MT7621, a far
//     REALITY server; p99 2.2–3.1 s by client), rounded up. A way that fails does it in about
//     0.1–0.6 s (refused, reset) or hangs (a TLS handshake that never ends): the wait is what a
//     hanging way costs.
//   - Body 1 s: the longest pause inside a body that came, 0.94 s (p99 0.11–0.13 s), rounded up;
//     the files were up to 260 KB. Past Large (1 MiB) received the pause may be 3 s (LargeBody):
//     the next way would hold a second copy of a big list at once, for a pause the measurement
//     did not cover.
//   - Most 3: not measured — bursts of TLS hellos to one name are what the DPI of some ISPs
//     penalises.
var downloadPlan = DownloadPlan{Wait: 4 * time.Second, Body: time.Second, LargeBody: 3 * time.Second, Large: 1 << 20, Most: 3}

// downloadWatch is how often a download looks at its ways under way.
const downloadWatch = 100 * time.Millisecond

// checkOutbounds tells a client whose outbounds come with a detour or fallbacks: which of them
// a caller takes would depend on the caller.
func checkOutbounds(define option.HTTPClient) error {
	if len(define.Outbounds) == 0 {
		return nil
	}
	if define.Detour != "" {
		return E.New("http_client[", define.Tag, "]: outbounds and detour together")
	}
	if len(define.Fallback) > 0 {
		return E.New("http_client[", define.Tag, "]: outbounds and fallback together")
	}
	return nil
}

// clientOptions are the options of the transport of a client: one with outbounds goes through
// the first of them for a caller that does not know the downloader.
func clientOptions(define option.HTTPClient) option.HTTPClientOptions {
	options := define.Options()
	if len(options.Outbounds) > 0 && options.Detour == "" {
		options.Detour = options.Outbounds[0]
		// a way may be a direct outbound with no options of its own: the way of no proxy
		options.DisableEmptyDirectCheck = true
	}
	options.Outbounds = nil
	return options
}

// ResolveDownloader is the downloader of the client the options name, or of the default client
// for nil; nil when that client has no outbounds. A client has one downloader, whoever asks.
func (m *Manager) ResolveDownloader(options *option.HTTPClientOptions) (adapter.HTTPDownloader, error) {
	var tag string
	switch {
	case options == nil:
		tag = m.defaultTag
	case options.Tag != "":
		tag = options.Tag
	case len(options.Outbounds) > 0:
		return nil, E.New("an http client with outbounds is one of http_clients, named by its tag")
	}
	if tag == "" {
		return nil, nil
	}
	m.access.Lock()
	defer m.access.Unlock()
	if downloader, loaded := m.downloaders[tag]; loaded {
		return downloader, nil
	}
	define, loaded := m.defines[tag]
	if !loaded {
		return nil, E.New("http_client not found: ", tag)
	}
	if len(define.Outbounds) == 0 {
		return nil, nil
	}
	err := checkOutbounds(define)
	if err != nil {
		return nil, err
	}
	var ways []string
	transports := make(map[string]adapter.HTTPTransport)
	for _, outbound := range define.Outbounds {
		if _, loaded := transports[outbound]; loaded {
			continue
		}
		wayOptions := define.Options()
		wayOptions.Detour = outbound
		wayOptions.Outbounds = nil
		wayOptions.DisableEmptyDirectCheck = true
		transport, err := NewTransport(m.ctx, m.logger, tag, wayOptions)
		if err != nil {
			return nil, E.Cause(err, "http_client[", tag, "] through ", outbound)
		}
		m.managedTransports = append(m.managedTransports, transport)
		ways = append(ways, outbound)
		transports[outbound] = transport
	}
	downloader := NewDownloader(m.logger, ways, transports, m.memory, service.PtrFromContext[urltest.HistoryStorage](m.ctx))
	downloader.Outbounds = service.FromContext[adapter.OutboundManager](m.ctx)
	if m.downloaders == nil {
		m.downloaders = make(map[string]*Downloader)
	}
	m.downloaders[tag] = downloader
	return downloader, nil
}

// Downloader downloads through the outbounds of a client (adapter.HTTPDownloader).
type Downloader struct {
	logger  logger.ContextLogger
	ways    []string
	pools   map[string]*wayPool
	memory  *DownloadMemory
	history *urltest.HistoryStorage
	// Plan is the plan of its downloads, downloadPlan when made
	Plan DownloadPlan
	// Outbounds, when set, tell a way that is a group: its delay is that of the outbound it
	// uses now
	Outbounds adapter.OutboundManager
}

// NewDownloader makes a downloader of the ways (outbound tags, the first one the default first
// try), each with its transport; history may be nil.
func NewDownloader(logger logger.ContextLogger, ways []string, transports map[string]adapter.HTTPTransport, memory *DownloadMemory, history *urltest.HistoryStorage) *Downloader {
	if memory == nil {
		memory = NewDownloadMemory()
	}
	pools := make(map[string]*wayPool, len(ways))
	for _, way := range ways {
		pools[way] = &wayPool{transport: transports[way]}
	}
	return &Downloader{logger: logger, ways: ways, pools: pools, memory: memory, history: history, Plan: downloadPlan}
}

// wayPool counts the users of the transport of a way, as sharedRef counts those of a shared
// client: the downloads under way through it, and the holds (Hold). Its idle connections are
// closed when the last user is done, so the downloads of several callers through one way keep
// their pooled connections while any of them uses it.
type wayPool struct {
	transport adapter.HTTPTransport
	users     atomic.Int32
}

func (p *wayPool) ref() *wayRef {
	p.users.Add(1)
	return &wayRef{pool: p}
}

// wayRef is one user of a way. Its CloseIdleConnections is its release, once; a round trip after
// it takes it again (as sharedRef). Reset resets the transport of the way, for every user.
type wayRef struct {
	pool     *wayPool
	released atomic.Bool
}

func (r *wayRef) RoundTrip(request *http.Request) (*http.Response, error) {
	if r.pool.transport == nil {
		return nil, E.New("no transport of the way")
	}
	if r.released.CompareAndSwap(true, false) {
		r.pool.users.Add(1)
	}
	return r.pool.transport.RoundTrip(request)
}

func (r *wayRef) CloseIdleConnections() {
	if r.released.CompareAndSwap(false, true) && r.pool.users.Add(-1) == 0 && r.pool.transport != nil {
		r.pool.transport.CloseIdleConnections()
	}
}

func (r *wayRef) Reset() {
	if r.pool.transport != nil {
		r.pool.transport.Reset()
	}
}

// Hold keeps the pooled connections of every way until its CloseIdleConnections: a box registers
// it with the start of its rule sets (adapter.HTTPStartContext), so the downloads of the start
// share their connections, closed when the start is over.
func (d *Downloader) Hold() adapter.HTTPTransport {
	refs := make(heldWays, 0, len(d.ways))
	for _, way := range d.ways {
		refs = append(refs, d.pools[way].ref())
	}
	return refs
}

// heldWays is a hold of the ways of a downloader: no transport of its own.
type heldWays []*wayRef

func (h heldWays) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, E.New("a hold of the ways of a downloader carries no request")
}

func (h heldWays) CloseIdleConnections() {
	for _, ref := range h {
		ref.CloseIdleConnections()
	}
}

func (h heldWays) Reset() {}

// delayHops bounds the groups of groups delay follows.
const delayHops = 4

func (d *Downloader) delay(way string) (uint16, bool) {
	for range delayHops {
		if d.Outbounds == nil {
			break
		}
		outbound, loaded := d.Outbounds.Outbound(way)
		if !loaded {
			break
		}
		group, isGroup := outbound.(adapter.OutboundGroup)
		if !isGroup {
			break
		}
		selected := group.Selected(N.NetworkTCP)
		if selected == nil {
			break
		}
		way = selected.Tag()
	}
	history := d.history.LoadURLTestHistory(way)
	if history == nil {
		return 0, false
	}
	return history.Delay, true
}

func (d *Downloader) Ways(host string) ([]string, bool) {
	ways := make([]string, 0, len(d.ways))
	for _, way := range d.ways {
		if d.allowed(way) {
			ways = append(ways, way)
		}
	}
	return d.memory.order(host, ways, d.delay)
}

// allowed tells a way that goes through no outbound the program excluded (SetExcluded), its
// groups followed to the outbound they use now: a group is passed by only while it uses an
// excluded one.
func (d *Downloader) allowed(way string) bool {
	for range delayHops + 1 {
		if d.memory.isExcluded(way) {
			return false
		}
		if d.Outbounds == nil {
			return true
		}
		outbound, loaded := d.Outbounds.Outbound(way)
		if !loaded {
			return true
		}
		group, isGroup := outbound.(adapter.OutboundGroup)
		if !isGroup {
			return true
		}
		selected := group.Selected(N.NetworkTCP)
		if selected == nil {
			return true
		}
		way = selected.Tag()
	}
	return true
}

func (d *Downloader) Record(host string, way string, err error, took time.Duration, bytes int64) {
	if err != nil {
		d.memory.failed(host, way)
		return
	}
	d.memory.brought(host, way, took, bytes)
}

// attempt is a way of a download under way or done.
type attempt struct {
	way     string
	started time.Time
	cancel  context.CancelFunc

	access   sync.Mutex
	last     time.Time
	body     bool
	bytes    int64
	finished bool
	took     time.Duration
	result   any
	err      error
}

func (a *attempt) progress(bytes int) {
	a.access.Lock()
	defer a.access.Unlock()
	a.body = true
	a.bytes += int64(bytes)
	a.last = time.Now()
}

func (a *attempt) finish(result any, err error) {
	a.access.Lock()
	defer a.access.Unlock()
	a.finished = true
	a.took = time.Since(a.started)
	a.result, a.err = result, err
}

func (d *Downloader) Download(ctx context.Context, host string, try adapter.HTTPDownloadTry, accept func(way string, result any) error) (string, error) {
	order, together := d.Ways(host)
	if len(order) == 0 {
		return "", E.New("no way to download through")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// buffered for every way: a way that ends after the download returned does not block
	done := make(chan *attempt, len(order))
	var attempts []*attempt
	next, running := 0, 0
	start := func() {
		way := order[next]
		next++
		attemptContext, attemptCancel := context.WithCancel(ctx)
		now := time.Now()
		item := &attempt{way: way, started: now, last: now, cancel: attemptCancel}
		attempts = append(attempts, item)
		running++
		// a user of the way of its own: a caller that closes the idle connections of its client
		// (a rule set after its update) closes those of the way only when no other download, nor
		// a hold, uses it
		ref := d.pools[way].ref()
		client := &http.Client{Transport: ref}
		d.logger.DebugContext(ctx, "download from ", host, " through ", way)
		go func() {
			result, err := try(attemptContext, way, client, item.progress)
			ref.CloseIdleConnections()
			item.finish(result, err)
			done <- item
		}()
	}
	start()
	if together && next < len(order) {
		start()
	}
	watch := time.NewTicker(downloadWatch)
	defer watch.Stop()
	var errs []error
	for {
		select {
		case item := <-done:
			running--
			item.cancel()
			err := item.err
			if err == nil {
				err = accept(item.way, item.result)
				if err == nil {
					d.memory.brought(host, item.way, item.took, item.bytes)
					return item.way, nil
				}
			}
			if ctx.Err() == nil {
				// a way cut by the caller's deadline is not known to be bad
				d.memory.failed(host, item.way)
			}
			errs = append(errs, E.Cause(err, item.way))
			if next < len(order) || running > 0 {
				d.logger.InfoContext(ctx, "download from ", host, " through ", item.way, " failed: ", err)
			}
			if next < len(order) {
				if running < d.Plan.Most {
					start()
				}
			} else if running == 0 {
				return "", E.Errors(errs...)
			}
		case <-watch.C:
			if next < len(order) && running < d.Plan.Most && d.due(attempts) {
				start()
			}
		case <-ctx.Done():
			return "", E.Errors(append(errs, ctx.Err())...)
		}
	}
}

// due tells whether the ways under way have earned the start of the next one (DownloadPlan).
func (d *Downloader) due(attempts []*attempt) bool {
	now := time.Now()
	idle := time.Duration(-1)
	stalled := false
	for _, item := range attempts {
		item.access.Lock()
		finished, last, inBody, bytes := item.finished, item.last, item.body, item.bytes
		item.access.Unlock()
		if finished {
			continue
		}
		pause := now.Sub(last)
		if inBody {
			limit := d.Plan.Body
			if bytes >= d.Plan.Large {
				limit = d.Plan.LargeBody
			}
			if pause < limit {
				// a body is coming: a second one would hold another copy of the file
				return false
			}
			stalled = true
			continue
		}
		if idle < 0 || pause < idle {
			idle = pause
		}
	}
	if stalled || idle < 0 {
		return true
	}
	return idle >= d.Plan.Wait
}

// DownloadMemory is what the downloads found of the ways: per host, the way that brought its last
// file and the ways that failed for it since they last brought one; per way, its last download
// that brought a file. A host process that keeps one in the context of its boxes
// (service.ContextWithPtr) keeps it across them.
type DownloadMemory struct {
	access sync.Mutex
	hosts  map[string]*hostRecord
	ways   map[string]*wayRecord
	// excluded are the outbounds no download goes through (SetExcluded)
	excluded map[string]bool
}

type hostRecord struct {
	brought string
	failed  map[string]time.Time
	used    time.Time
}

type wayRecord struct {
	brought time.Time
	// bytes a second of that download
	rate float64
}

// memoryHosts bounds the hosts a memory keeps, the least recently used forgotten first: a box
// downloads from a few hosts; a bound only against a caller that asks for many.
const memoryHosts = 256

func NewDownloadMemory() *DownloadMemory {
	return &DownloadMemory{hosts: make(map[string]*hostRecord), ways: make(map[string]*wayRecord)}
}

func (m *DownloadMemory) host(name string) *hostRecord {
	record := m.hosts[name]
	if record == nil {
		if len(m.hosts) >= memoryHosts {
			var oldest string
			for key, item := range m.hosts {
				if oldest == "" || item.used.Before(m.hosts[oldest].used) {
					oldest = key
				}
			}
			delete(m.hosts, oldest)
		}
		record = &hostRecord{failed: make(map[string]time.Time)}
		m.hosts[name] = record
	}
	record.used = time.Now()
	return record
}

func (m *DownloadMemory) brought(host string, way string, took time.Duration, bytes int64) {
	m.access.Lock()
	defer m.access.Unlock()
	record := m.host(host)
	record.brought = way
	delete(record.failed, way)
	rate := float64(bytes)
	if took > 0 {
		rate = float64(bytes) / took.Seconds()
	}
	m.ways[way] = &wayRecord{brought: time.Now(), rate: rate}
}

func (m *DownloadMemory) failed(host string, way string) {
	m.access.Lock()
	defer m.access.Unlock()
	record := m.host(host)
	if record.brought == way {
		record.brought = ""
	}
	record.failed[way] = time.Now()
}

// SetExcluded sets the outbounds no download goes through, by tag, in place of those set before:
// the choice of the program that runs the boxes (a server of little traffic, one kept as the last
// reserve of a rule, a tunnel to a closed network). They are not in the configuration, whose
// http_clients would change with every new list of servers.
func (m *DownloadMemory) SetExcluded(tags []string) {
	excluded := make(map[string]bool, len(tags))
	for _, tag := range tags {
		excluded[tag] = true
	}
	m.access.Lock()
	defer m.access.Unlock()
	m.excluded = excluded
}

func (m *DownloadMemory) isExcluded(tag string) bool {
	m.access.Lock()
	defer m.access.Unlock()
	return m.excluded[tag]
}

// Forget forgets what the downloads found of a way: its tag names another outbound now. A nil
// memory has nothing to forget.
func (m *DownloadMemory) Forget(way string) {
	if m == nil {
		return
	}
	m.access.Lock()
	defer m.access.Unlock()
	delete(m.ways, way)
	for _, record := range m.hosts {
		if record.brought == way {
			record.brought = ""
		}
		delete(record.failed, way)
	}
}

// order is the ways of a download from host in the order they are tried: the way that brought
// its last file; the first way of the list; the ways that brought a file of another host, the
// fastest first; those the URL tests passed, the lowest delay first (a group by the outbound it
// uses now); those not known, in the order of the list; those that failed for the host, the oldest failure first. No way is left
// out. together tells that the first failed for the host last time: the second starts with it.
func (m *DownloadMemory) order(host string, ways []string, delay func(string) (uint16, bool)) ([]string, bool) {
	if len(ways) == 0 {
		return nil, false
	}
	m.access.Lock()
	defer m.access.Unlock()
	record := m.hosts[host]
	if record != nil {
		record.used = time.Now()
	}
	order := make([]string, 0, len(ways))
	if record != nil && record.brought != "" && slices.Contains(ways, record.brought) {
		order = append(order, record.brought)
	}
	if !slices.Contains(order, ways[0]) {
		order = append(order, ways[0])
	}
	type ranked struct {
		way   string
		class int
		key   float64
	}
	var rest []ranked
	for _, way := range ways[1:] {
		if slices.Contains(order, way) || slices.ContainsFunc(rest, func(item ranked) bool { return item.way == way }) {
			continue
		}
		item := ranked{way: way, class: 3}
		var failedAt time.Time
		if record != nil {
			failedAt = record.failed[way]
		}
		switch {
		case !failedAt.IsZero():
			item.class, item.key = 4, float64(failedAt.UnixNano())
		case m.ways[way] != nil:
			item.class, item.key = 1, -m.ways[way].rate
		default:
			if value, tested := delay(way); tested {
				item.class, item.key = 2, float64(value)
			}
		}
		rest = append(rest, item)
	}
	slices.SortStableFunc(rest, func(left ranked, right ranked) int {
		if left.class != right.class {
			return left.class - right.class
		}
		return cmp.Compare(left.key, right.key)
	})
	for _, item := range rest {
		order = append(order, item.way)
	}
	together := record != nil && len(order) > 1 && !record.failed[order[0]].IsZero()
	return order, together
}

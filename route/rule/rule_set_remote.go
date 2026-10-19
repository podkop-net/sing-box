package rule

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/domainset"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"go4.org/netipx"
)

var _ adapter.RuleSet = (*RemoteRuleSet)(nil)

type RemoteRuleSet struct {
	ctx            context.Context
	cancel         context.CancelFunc
	logger         logger.ContextLogger
	outbound       adapter.OutboundManager
	options        option.RuleSet
	updateInterval time.Duration
	dialer         N.Dialer
	access         sync.RWMutex
	rules          []adapter.HeadlessRule
	metadata       adapter.RuleSetMetadata
	lastUpdated    time.Time
	lastEtag       string
	updateTicker   *time.Ticker
	cacheFile      adapter.CacheFile
	pauseManager   pause.Manager
	callbacks      list.List[adapter.RuleSetUpdateCallback]
	refs           atomic.Int32
	// the updater's own: whether the last fetch loaded a list, and the failed updates
	// since the last success (see fetchFailed)
	fetchLoaded   bool
	failures      int
	failureLogged time.Time
}

func NewRemoteRuleSet(ctx context.Context, logger logger.ContextLogger, options option.RuleSet) *RemoteRuleSet {
	ctx, cancel := context.WithCancel(ctx)
	var updateInterval time.Duration
	if options.RemoteOptions.UpdateInterval > 0 {
		updateInterval = time.Duration(options.RemoteOptions.UpdateInterval)
	} else {
		updateInterval = 24 * time.Hour
	}
	return &RemoteRuleSet{
		ctx:            ctx,
		cancel:         cancel,
		outbound:       service.FromContext[adapter.OutboundManager](ctx),
		logger:         logger,
		options:        options,
		updateInterval: updateInterval,
		pauseManager:   service.FromContext[pause.Manager](ctx),
	}
}

func (s *RemoteRuleSet) Name() string {
	return s.options.Tag
}

func (s *RemoteRuleSet) String() string {
	return strings.Join(F.MapToString(s.currentRules()), " ")
}

// currentRules reads the rules under the lock that loadBytes swaps them under: since the
// start deadline (podkop-engine) a set routinely gets its rules while connections match it.
func (s *RemoteRuleSet) currentRules() []adapter.HeadlessRule {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.rules
}

// dropRules forgets the rules, under the same lock.
func (s *RemoteRuleSet) dropRules() {
	s.access.Lock()
	s.rules = nil
	s.access.Unlock()
}

func (s *RemoteRuleSet) StartContext(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	s.cacheFile = service.FromContext[adapter.CacheFile](s.ctx)
	var dialer N.Dialer
	if s.options.RemoteOptions.DownloadDetour != "" {
		outbound, loaded := s.outbound.Outbound(s.options.RemoteOptions.DownloadDetour)
		if !loaded {
			return E.New("download detour not found: ", s.options.RemoteOptions.DownloadDetour)
		}
		dialer = outbound
	} else {
		dialer = s.outbound.Default()
	}
	s.dialer = dialer
	if s.cacheFile != nil {
		if savedSet := s.cacheFile.LoadRuleSet(s.options.Tag); savedSet != nil {
			err := s.loadBytes(savedSet.Content)
			if err != nil {
				s.logger.Warn(E.Cause(err, "restore cached rule-set, will refetch"))
			} else {
				s.lastUpdated = savedSet.LastUpdated
				s.lastEtag = savedSet.LastEtag
			}
		}
	}
	if s.lastUpdated.IsZero() {
		err := s.fetch(ctx, startContext)
		if err != nil {
			// Start with an empty rule-set instead of failing the whole start:
			// loopUpdate keeps retrying until the first download succeeds.
			s.logger.Error("initial rule-set: ", s.options.Tag, ", starting empty and retrying: ", logText(err))
		}
	}
	s.updateTicker = time.NewTicker(s.updateInterval)
	return nil
}

func (s *RemoteRuleSet) PostStart() error {
	go s.loopUpdate()
	return nil
}

func (s *RemoteRuleSet) Metadata() adapter.RuleSetMetadata {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.metadata
}

func (s *RemoteRuleSet) ExtractIPSet() []*netipx.IPSet {
	s.access.RLock()
	defer s.access.RUnlock()
	return common.FlatMap(s.rules, extractIPSetFromRule)
}

func (s *RemoteRuleSet) IncRef() {
	s.refs.Add(1)
}

func (s *RemoteRuleSet) DecRef() {
	if s.refs.Add(-1) < 0 {
		panic("rule-set: negative refs")
	}
}

func (s *RemoteRuleSet) Cleanup() {
	if s.refs.Load() == 0 {
		s.dropRules()
	}
}

func (s *RemoteRuleSet) RegisterCallback(callback adapter.RuleSetUpdateCallback) *list.Element[adapter.RuleSetUpdateCallback] {
	s.access.Lock()
	defer s.access.Unlock()
	return s.callbacks.PushBack(callback)
}

func (s *RemoteRuleSet) UnregisterCallback(element *list.Element[adapter.RuleSetUpdateCallback]) {
	s.access.Lock()
	defer s.access.Unlock()
	s.callbacks.Remove(element)
}

func (s *RemoteRuleSet) loadBytes(content []byte) error {
	var (
		ruleSet option.PlainRuleSetCompat
		err     error
	)
	switch s.options.Format {
	case C.RuleSetFormatSource:
		ruleSet, err = domainset.ReadSource(content)
		if err != nil {
			return err
		}
	case C.RuleSetFormatBinary:
		ruleSet, err = srs.ReadSets(bytes.NewReader(content))
		if err != nil {
			return err
		}
	default:
		return E.New("unknown rule-set format: ", s.options.Format)
	}
	plainRuleSet, err := ruleSet.Upgrade()
	if err != nil {
		return err
	}
	rules := make([]adapter.HeadlessRule, len(plainRuleSet.Rules))
	for i, ruleOptions := range plainRuleSet.Rules {
		rules[i], err = NewHeadlessRule(s.ctx, ruleOptions)
		if err != nil {
			return E.Cause(err, "parse rule_set.rules.[", i, "]")
		}
	}
	s.access.Lock()
	s.metadata.ContainsProcessRule = HasHeadlessRule(plainRuleSet.Rules, isProcessHeadlessRule)
	s.metadata.ContainsWIFIRule = HasHeadlessRule(plainRuleSet.Rules, isWIFIHeadlessRule)
	s.metadata.ContainsIPCIDRRule = HasHeadlessRule(plainRuleSet.Rules, isIPCIDRHeadlessRule)
	s.rules = rules
	callbacks := s.callbacks.Array()
	s.access.Unlock()
	for _, callback := range callbacks {
		callback(s)
	}
	return nil
}

func (s *RemoteRuleSet) loopUpdate() {
	// Never downloaded (initial fetch failed): retry with backoff instead of
	// waiting a whole update_interval.
	for delay := 5 * time.Second; s.lastUpdated.IsZero(); delay = min(delay*2, 30*time.Second) {
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(delay):
		}
		if s.updateOnce() {
			notifyRuleSetRecovered(s.logger, s.options.Tag)
			runtime.GC()
		}
	}
	if time.Since(s.lastUpdated) > s.updateInterval {
		s.updateOnce()
	}
	runtime.GC()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.updateTicker.C:
			// the old list is garbage once a new one is loaded; a failed or not-modified
			// update leaves nothing to collect
			if s.updateOnce() {
				runtime.GC()
			}
		}
	}
}

// updateOnce updates the rule-set and reports whether it loaded a new list.
func (s *RemoteRuleSet) updateOnce() bool {
	s.fetchLoaded = false
	err := s.fetch(s.ctx, nil)
	if err != nil {
		if s.ctx.Err() != nil {
			// cut by the shutdown, not a failed update
			return false
		}
		s.fetchFailed(err)
		return false
	}
	if s.failures > 0 {
		s.logger.Info("fetch rule-set ", s.options.Tag, ": succeeded after ", s.failures, " failed attempts")
		s.failures = 0
	}
	if s.refs.Load() == 0 {
		s.dropRules()
	}
	return s.fetchLoaded
}

// ruleSetFailureLogInterval is how often a rule-set that keeps failing to update logs its
// failures as an error.
const ruleSetFailureLogInterval = 10 * time.Minute

// fetchFailed logs a failed update: the first of a series as an error, then a count with
// the last error once every ruleSetFailureLogInterval, the others at debug. A list that
// never came at the start is retried every 30 s, which logged 2880 errors a day.
func (s *RemoteRuleSet) fetchFailed(err error) {
	s.failures++
	switch {
	case s.failures == 1:
		s.failureLogged = time.Now()
		s.logger.Error("fetch rule-set ", s.options.Tag, ": ", logText(err))
	case time.Since(s.failureLogged) >= ruleSetFailureLogInterval:
		s.failureLogged = time.Now()
		s.logger.Error("fetch rule-set ", s.options.Tag, ": ", s.failures, " failed attempts, the last: ", logText(err))
	default:
		s.logger.Debug("fetch rule-set ", s.options.Tag, ": ", logText(err))
	}
}

// logText makes one line of the error of a fetch. It may carry what the server sent: the
// status line of the answer, the text of a rule that does not parse. That text is cut,
// and what is not printable in it is replaced.
func logText(err error) string {
	text := err.Error()
	if len(text) > 512 {
		text = strings.ToValidUTF8(text[:512], "") + "..."
	}
	return strings.Map(func(r rune) rune {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			return '?'
		}
		return r
	}, text)
}

// A rule-set download must not hang the start (the inbounds listen only after every rule-set
// has started) nor the background updates, yet a large list on a slow router link is normal
// and must still load. So the start gets a short TOTAL deadline — on timeout it starts empty
// and the updater fills it in later — while every fetch, start or update, is bounded by a
// no-progress (stall) timer that fires only when the transfer delivers nothing for a while,
// never cutting off a slow but steady download. ruleSetMaxSize caps the bytes read into
// memory: a backstop against an endless stream, not a memory guarantee (parsing a list costs
// several times its wire size, so a genuinely large list is a separate memory concern).
var (
	ruleSetStartDeadline = 30 * time.Second
	ruleSetStallTimeout  = 30 * time.Second
	ruleSetMaxSize       = 50 << 20
)

// stallResetReader resets a watchdog on every read that carries data, so a transfer making
// steady progress is never cut off while one that goes silent is.
type stallResetReader struct {
	reader io.Reader
	reset  func()
}

func (r *stallResetReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.reset()
	}
	return n, err
}

// readRuleSetBody reads the body of a 200 response. What cannot be a rule-set is refused
// before it is held in memory: a declared length above the cap, and for the binary format a
// body that does not start with the magic bytes (an error or login page served with status
// 200). The slice is sized by the declared length, so a normal download is read without
// regrowing.
func (s *RemoteRuleSet) readRuleSetBody(response *http.Response, body io.Reader) ([]byte, error) {
	if response.ContentLength > int64(ruleSetMaxSize) {
		return nil, E.New("rule-set larger than ", ruleSetMaxSize>>20, " MB")
	}
	reader := bufio.NewReader(io.LimitReader(body, int64(ruleSetMaxSize)+1))
	if s.options.Format == C.RuleSetFormatBinary {
		head, err := reader.Peek(len(srs.MagicBytes))
		if err != nil && err != io.EOF {
			return nil, err
		}
		if !bytes.Equal(head, srs.MagicBytes[:]) {
			sample, _ := reader.Peek(ruleSetSampleSize)
			return nil, E.New("not a binary rule-set: ", describeRuleSetBody(response, response.ContentLength, sample))
		}
	}
	capacity := 512
	if response.ContentLength > 0 {
		// one byte more: the read that finds the end must not regrow the slice
		capacity = int(response.ContentLength) + 1
	}
	content := make([]byte, 0, capacity)
	for {
		if len(content) == cap(content) {
			content = append(content, 0)[:len(content)]
		}
		n, err := reader.Read(content[len(content):cap(content)])
		content = content[:len(content)+n]
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if len(content) > ruleSetMaxSize {
		return nil, E.New("rule-set larger than ", ruleSetMaxSize>>20, " MB")
	}
	return content, nil
}

// ruleSetSampleSize is how much of a body that is not a rule-set an error shows.
const ruleSetSampleSize = 16

// describeRuleSetBody tells a page from a damaged file in the log: the size, the declared
// type and the first bytes. The header and the bytes come from the server, so they are
// quoted and cut.
func describeRuleSetBody(response *http.Response, size int64, sample []byte) string {
	var description strings.Builder
	if size >= 0 {
		description.WriteString(strconv.FormatInt(size, 10))
		description.WriteString(" bytes, ")
	}
	contentType := response.Header.Get("Content-Type")
	if len(contentType) > 64 {
		contentType = contentType[:64]
	}
	description.WriteString("Content-Type ")
	description.WriteString(strconv.Quote(contentType))
	if len(sample) > ruleSetSampleSize {
		sample = sample[:ruleSetSampleSize]
	}
	description.WriteString(", starts with ")
	description.WriteString(strconv.Quote(string(sample)))
	return description.String()
}

func (s *RemoteRuleSet) fetch(ctx context.Context, startContext *adapter.HTTPStartContext) error {
	s.logger.Debug("updating rule-set ", s.options.Tag, " from URL: ", s.options.RemoteOptions.URL)
	// a group that switches members closes the connections it does not know as routed
	// ones: a list half downloaded through it would wait for the next update_interval
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if startContext != nil {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, ruleSetStartDeadline)
		defer stop()
	}
	// Fire the stall timer if the request produces nothing (no response headers, then no body
	// bytes) for the stall timeout; each read that carries data resets it below.
	var stalled atomic.Bool
	stall := time.AfterFunc(ruleSetStallTimeout, func() {
		stalled.Store(true)
		cancel()
	})
	defer stall.Stop()
	// name the bound that cut the fetch: the context errors alone read like a shutdown
	describe := func(err error) error {
		if stalled.Load() {
			return E.Cause(err, "no data for ", ruleSetStallTimeout)
		}
		if startContext != nil && errors.Is(err, context.DeadlineExceeded) {
			return E.Cause(err, "start deadline of ", ruleSetStartDeadline, " reached")
		}
		return err
	}
	var httpClient *http.Client
	if startContext != nil {
		httpClient = startContext.HTTPClient(s.options.RemoteOptions.DownloadDetour, s.dialer)
	} else {
		httpClient = &http.Client{
			Transport: &http.Transport{
				ForceAttemptHTTP2:   true,
				TLSHandshakeTimeout: C.TCPTimeout,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return s.dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
				},
				TLSClientConfig: &tls.Config{
					Time:    ntp.TimeFuncFromContext(s.ctx),
					RootCAs: adapter.RootPoolFromContext(s.ctx),
				},
			},
		}
		// The client is thrown away after this fetch: do not leave its connections open.
		defer httpClient.CloseIdleConnections()
	}
	request, err := http.NewRequest("GET", s.options.RemoteOptions.URL, nil)
	if err != nil {
		return err
	}
	if s.lastEtag != "" {
		request.Header.Set("If-None-Match", s.lastEtag)
	}
	response, err := httpClient.Do(request.WithContext(ctx))
	if err != nil {
		if startContext != nil {
			// the start fetches share this client's pooled connections: one that stalled
			// would carry the next batch of rule-sets into the same wait
			httpClient.CloseIdleConnections()
		}
		return describe(err)
	}
	// Also on an unexpected status, otherwise the connection stays open.
	defer response.Body.Close()
	stall.Reset(ruleSetStallTimeout)
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		s.lastUpdated = time.Now()
		if s.cacheFile != nil {
			savedRuleSet := s.cacheFile.LoadRuleSet(s.options.Tag)
			if savedRuleSet != nil {
				savedRuleSet.LastUpdated = s.lastUpdated
				err = s.cacheFile.SaveRuleSet(s.options.Tag, savedRuleSet)
				if err != nil {
					s.logger.Error("save rule-set updated time: ", err)
					return nil
				}
			}
		}
		s.logger.Info("update rule-set ", s.options.Tag, ": not modified")
		return nil
	default:
		return E.New("unexpected status: ", response.Status)
	}
	body := &stallResetReader{reader: response.Body, reset: func() { stall.Reset(ruleSetStallTimeout) }}
	content, err := s.readRuleSetBody(response, body)
	// the transfer is over: parsing a large list must not look like a stalled download
	stall.Stop()
	if err != nil {
		response.Body.Close()
		return describe(err)
	}
	// a rule-set closed while its list came in does not parse it: the parse of a big list
	// is the most an update costs, and a box that replaces this one fetches its own
	if s.ctx.Err() != nil {
		response.Body.Close()
		return s.ctx.Err()
	}
	err = s.loadBytes(content)
	if err != nil {
		response.Body.Close()
		return E.Cause(err, "read rule-set (", describeRuleSetBody(response, int64(len(content)), content), ")")
	}
	response.Body.Close()
	if s.ctx.Err() != nil {
		// closed during the parse: its cache file is closed too
		return s.ctx.Err()
	}
	s.fetchLoaded = true
	eTagHeader := response.Header.Get("Etag")
	if eTagHeader != "" {
		s.lastEtag = eTagHeader
	}
	s.lastUpdated = time.Now()
	if s.cacheFile != nil {
		err = s.cacheFile.SaveRuleSet(s.options.Tag, &adapter.SavedBinary{
			LastUpdated: s.lastUpdated,
			Content:     content,
			LastEtag:    s.lastEtag,
		})
		if err != nil {
			s.logger.Error("save rule-set cache: ", err)
		}
	}
	s.logger.Info("updated rule-set ", s.options.Tag)
	return nil
}

func (s *RemoteRuleSet) Close() error {
	s.dropRules()
	s.cancel()
	if s.updateTicker != nil {
		s.updateTicker.Stop()
	}
	return nil
}

func (s *RemoteRuleSet) Match(metadata *adapter.InboundContext) bool {
	return !s.matchStates(metadata).isEmpty()
}

func (s *RemoteRuleSet) matchStates(metadata *adapter.InboundContext) ruleMatchStateSet {
	return s.matchStatesWithBase(metadata, 0)
}

func (s *RemoteRuleSet) matchStatesWithBase(metadata *adapter.InboundContext, base ruleMatchState) ruleMatchStateSet {
	var stateSet, definitiveStateSet ruleMatchStateSet
	for _, rule := range s.currentRules() {
		nestedMetadata := *metadata
		nestedMetadata.ResetRuleMatchCache()
		stateSet = stateSet.merge(matchHeadlessRuleStatesWithBase(rule, &nestedMetadata, base))
		definitiveStateSet = definitiveStateSet.merge(ruleMatchStateSet(nestedMetadata.DefinitiveMatchStates))
	}
	metadata.DefinitiveMatchStates = uint16(definitiveStateSet)
	return stateSet
}

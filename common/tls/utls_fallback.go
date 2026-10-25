//go:build with_utls

package tls

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	utls "github.com/metacubex/utls"
)

const (
	// handshakes of one dial; the next dial goes on with the list
	utlsFallbackAttempts = 4
	// local addresses whose choice is remembered
	utlsFallbackPaths = 8
	// The fingerprint with the X25519MLKEM768 key share that the fallback goes on to when the
	// ClientHello without the key share is refused (by a REALITY server since Xray-core
	// v26.9.8) or not let through. Measured in October 2026: it passes the Russian DPI that
	// freezes the connections of chrome (Chrome 133 with the key share), and of safari and
	// randomized as well, when many are made to one server at once.
	utlsFallbackWithKeyShare = "firefox"
	// lines remembered so as not to be repeated
	utlsFallbackLines = 64
	// times in a row a candidate may be answered again after it was not, before the next
	// time counts against it
	utlsFallbackAgain = 3
	// such a time is one of a row when the ClientHello that went unanswered was among
	// this many first ones sent since the rest before it ended
	utlsFallbackFirst = 10
)

var (
	// a configuration without the option experimental.utls_fallback turns the fallback on
	// with any value of SING_BOX_UTLS_FALLBACK
	utlsFallbackEnvironment = os.Getenv("SING_BOX_UTLS_FALLBACK")
	// a line that comes again within this time is counted, not written
	utlsFallbackLogInterval = 10 * time.Second
	// The fallback of a path rests when what leaves a ClientHello unanswered turns out
	// not to choose by the ClientHello: every candidate went unanswered (a block of the
	// address or of the name, a server that is down), or the one that went unanswered is
	// answered on another connection (a loss on the way). Another ClientHello does not help
	// there, and every further try is one more connection. While the fallback rests,
	// connections are made with the candidate that worked last, the configured fingerprint
	// when none has. The rest after the whole list is twice as long when the next one begins
	// as soon after it, up to the maximum.
	utlsFallbackRest    = 30 * time.Second
	utlsFallbackRestMax = 10 * time.Minute
	// without a ClientHello left unanswered for this long, what was before is forgotten
	utlsFallbackQuiet = 5 * time.Minute
	// A choice is kept this long, also across restarts in the cache file; then one dial
	// tries the first candidate again: the server may have been updated, the path changed.
	utlsFallbackRecheck = 24 * time.Hour
)

// utlsFallbackCandidate is a ClientHello the fallback may send: a fingerprint, with or
// without its X25519MLKEM768 key share.
type utlsFallbackCandidate struct {
	name    string
	id      utls.ClientHelloID
	noMLKEM bool
}

func (c utlsFallbackCandidate) String() string {
	if c.noMLKEM {
		return c.name + " without X25519MLKEM768"
	}
	return c.name
}

// utlsClassicFingerprint tells a fingerprint whose ClientHello carries no X25519MLKEM768
// key share.
func utlsClassicFingerprint(name string) bool {
	switch name {
	case "edge", "ios", "qq", "360", "android":
		return true
	}
	return false
}

// utlsFallbackPath is what the fallback has learned from one local address.
//
// A path begins with the first candidate, or with the one chosen for the server before (the
// cache file) when that was less than utlsFallbackRecheck ago. A server that refuses the
// ClientHello of a candidate (answers it as a stranger's) makes the path go on at once. A
// candidate is left for the next when its ClientHello goes unanswered; the first one, and
// one that has completed a handshake on this path, only when that happens on two
// connections in a row, the second made after the first was given up: one unanswered
// ClientHello may be a second of loss, while a new connection is made over a path that has
// just carried its SYN. When such a candidate is answered after all, the fallback rests
// (see above); after utlsFallbackAgain such rests in a row the next unanswered ClientHello
// counts at once: what drops a part of the ClientHellos of one kind looks like a loss each
// time. The rests are in a row when the ClientHello that began each was among the first
// utlsFallbackFirst sent since the rest before it: a filter that drops one kind in twenty or
// more does that as a rule, a loss of one ClientHello in a hundred seldom.
type utlsFallbackPath struct {
	local netip.Addr
	// the candidate in use
	position int
	// candidates left in a row, and of them those that the server answered and refused
	failed  int
	refused int
	// the candidates that have completed a handshake on this path, a bit each, and the
	// one that did last (-1: none); a candidate refused since is in neither
	worked uint64
	last   int
	// when the candidate in use was chosen or confirmed last
	chosen time.Time
	// a dial is trying the first candidate again, the choice being old
	rechecking bool
	// when the ClientHello of the candidate in use went unanswered for the first time
	suspected time.Time
	// rests in a row that the candidate in use began by being answered again, and the
	// ClientHellos sent with it and watched since the last of them ended
	again int
	sent  int
	// until when the fallback rests, and the candidate the path goes on with after the rest
	// (-1: the one it rests on)
	restUntil time.Time
	resume    int
	// the last rest after a whole list: how long it was, and when it ended
	rest           time.Duration
	exhaustedUntil time.Time
}

// twice tells whether the candidate in use is left only after two unanswered connections:
// the first one and one that has worked here.
func (p *utlsFallbackPath) twice() bool {
	return p.position == 0 || p.worked&(1<<p.position) != 0
}

type utlsFallbackLine struct {
	written time.Time
	// times it came again since it was written
	more int
}

// utlsFallback is shared by a client configuration and its clones.
type utlsFallback struct {
	logger logger.ContextLogger
	// the ClientHellos in the order they are tried
	candidates []utlsFallbackCandidate
	// the configured fingerprint as it is: what is used when nothing has worked
	configured int
	// with tls.spoof the forged ClientHello may be what the path does not let through: the
	// lines say so
	spoof bool
	// the cache file is found at the first dial: the box registers it after it has made the
	// outbounds, whose clients make the fallback
	ctx   context.Context
	cache adapter.CacheFile
	// what the choice of the server is kept under in the cache file: the configured
	// fingerprint, the server name and the server
	key    string
	access sync.Mutex
	paths  []*utlsFallbackPath
	lines  map[string]*utlsFallbackLine
	// the choice read from the cache file (-1: none) and when it was made
	saved   int
	savedAt time.Time
	// a candidate has completed a handshake or was read from the cache file: no dial waits
	known bool
	// while nothing is known, the dial that tries the candidates; the others wait for it
	// so that a burst of connections does not try all of them at once: a server refusing a
	// ClientHello counts every refusal, and a path freezes on a burst
	probing chan struct{}
	// until when a path rests: its dials are made as without the fallback, and none waits
	// for a probe, which would make them one at a time, each waiting out its timeout
	restUntil time.Time
}

// utlsFallbackEnabled tells whether the fallback is on: the option
// experimental.utls_fallback of the configuration when it is there, else the environment.
// The list of fingerprints the option may carry is no longer used: the candidates are
// fixed (newUTLSFallback).
func utlsFallbackEnabled(ctx context.Context) bool {
	configured := service.FromContext[*option.UTLSFallbackOptions](ctx)
	if configured == nil {
		return utlsFallbackEnvironment != ""
	}
	return configured.Enabled
}

// newUTLSFallback makes the fallback of a client with the fingerprint configured (of the ID
// configuredID), nil when it is off. Its candidates, each once:
//
//  1. the configured fingerprint without its X25519MLKEM768 key share, as stock sing-box sends
//     it under REALITY (a fingerprint without the key share as it is): a small ClientHello
//     that the DPI freezing chrome under bursts of connections lets through, and that every
//     server takes but a REALITY server since Xray-core v26.9.8;
//  2. firefox with the key share, which such a server takes and that DPI lets through;
//  3. the configured fingerprint as it is.
func newUTLSFallback(ctx context.Context, logger logger.ContextLogger, configured string, configuredID utls.ClientHelloID, reality bool, spoof bool) *utlsFallback {
	if !utlsFallbackEnabled(ctx) {
		return nil
	}
	if logger == nil {
		logger = log.StdLogger()
	}
	if configured == "" {
		configured = "chrome"
	}
	asConfigured := utlsFallbackCandidate{name: configured, id: configuredID}
	candidates := []utlsFallbackCandidate{asConfigured}
	if !utlsClassicFingerprint(configured) {
		candidates[0].noMLKEM = true
	}
	if configured != utlsFallbackWithKeyShare {
		id, err := uTLSClientHelloID(utlsFallbackWithKeyShare)
		if err == nil {
			candidates = append(candidates, utlsFallbackCandidate{name: utlsFallbackWithKeyShare, id: id})
		}
	}
	configuredIndex := -1
	for index, candidate := range candidates {
		if candidate == asConfigured {
			configuredIndex = index
		}
	}
	if configuredIndex < 0 {
		candidates = append(candidates, asConfigured)
		configuredIndex = len(candidates) - 1
	}
	if len(candidates) < 2 {
		return nil
	}
	return &utlsFallback{
		logger:     logger,
		candidates: candidates,
		configured: configuredIndex,
		spoof:      spoof,
		ctx:        ctx,
		lines:      make(map[string]*utlsFallbackLine),
		saved:      -1,
	}
}

// warn writes a line of the fallback, once in utlsFallbackLogInterval: a path that answers
// no ClientHello gives the same lines on every connection. The next time the line is
// written it says how many times it came meanwhile. The caller holds the lock.
func (f *utlsFallback) warn(message ...any) {
	text := F.ToString(message...)
	now := time.Now()
	line := f.lines[text]
	if line != nil && now.Sub(line.written) < utlsFallbackLogInterval {
		line.more++
		return
	}
	if line == nil {
		if len(f.lines) >= utlsFallbackLines {
			clear(f.lines)
		}
		line = new(utlsFallbackLine)
		f.lines[text] = line
	}
	if line.more > 0 {
		f.logger.Warn(text, " (", line.more, " more in the last ", now.Sub(line.written).Round(time.Second), ")")
	} else {
		f.logger.Warn(text)
	}
	line.written = now
	line.more = 0
}

// load reads the choice for the server from the cache file, once: the first dial gives the
// key. The caller holds the lock.
func (f *utlsFallback) load(serverName string, destination M.Socksaddr) {
	if f.key != "" {
		return
	}
	f.key = F.ToString(f.candidates[f.configured].name, " ", serverName, " ", destination)
	f.cache = service.FromContext[adapter.CacheFile](f.ctx)
	if f.cache == nil {
		return
	}
	choice, at, loaded := f.cache.LoadUTLSChoice(f.key)
	if !loaded || time.Since(at) >= utlsFallbackRecheck {
		return
	}
	for index, candidate := range f.candidates {
		if candidate.String() == choice {
			f.saved, f.savedAt = index, at
			f.known = true
			return
		}
	}
}

// store keeps the candidate in use of a path as the choice for the server. The caller holds
// the lock.
func (f *utlsFallback) store(path *utlsFallbackPath, now time.Time) {
	path.chosen = now
	f.saved, f.savedAt = path.position, now
	if f.cache != nil && f.key != "" {
		_ = f.cache.StoreUTLSChoice(f.key, f.candidates[path.position].String(), now)
	}
}

// path returns what is known of the local address of conn. The caller holds the lock.
func (f *utlsFallback) path(conn net.Conn) *utlsFallbackPath {
	local := M.AddrPortFromNet(conn.LocalAddr()).Addr().Unmap().WithZone("")
	for index, path := range f.paths {
		if path.local == local {
			// the most recently used first
			copy(f.paths[1:index+1], f.paths[:index])
			f.paths[0] = path
			return path
		}
	}
	path := &utlsFallbackPath{local: local, last: -1, resume: -1}
	if f.saved >= 0 {
		// what was chosen for the server before, on this or another address
		path.position, path.last, path.chosen = f.saved, f.saved, f.savedAt
		path.worked = 1 << f.saved
	}
	if len(f.paths) < utlsFallbackPaths {
		f.paths = append(f.paths, nil)
	}
	copy(f.paths[1:], f.paths)
	f.paths[0] = path
	return path
}

func (f *utlsFallback) names() string {
	names := ""
	for index, candidate := range f.candidates {
		if index > 0 {
			names += ", "
		}
		names += candidate.String()
	}
	return names
}

// advance takes the next candidate of a path. The caller holds the lock.
func (f *utlsFallback) advance(path *utlsFallbackPath) {
	path.position = (path.position + 1) % len(f.candidates)
	path.failed++
	path.suspected = time.Time{}
	path.again, path.sent = 0, 0
}

// rests puts the fallback of a path to rest for the given time, on the candidate that
// completed a handshake last, the configured fingerprint as it is when none has: its
// connections are made as without the fallback. After the rest the path goes on with that
// candidate, or tries the list again from the first when none has completed a handshake. The
// caller holds the lock.
func (f *utlsFallback) rests(path *utlsFallbackPath, now time.Time, rest time.Duration) {
	path.restUntil = now.Add(rest)
	if path.restUntil.After(f.restUntil) {
		f.restUntil = path.restUntil
	}
	path.position = path.last
	path.resume = -1
	if path.position < 0 {
		path.position = f.configured
		path.resume = 0
	}
	path.failed, path.refused = 0, 0
	path.suspected = time.Time{}
	path.sent = 0
}

// exhausted is the verdict of a list that was gone through without one handshake: the
// fallback rests, twice as long as the last time when that was not long ago. refusal is
// the failure of the candidate that closed the list, nil when its ClientHello went
// unanswered. It returns what the dial says of it. The caller holds the lock.
func (f *utlsFallback) exhausted(path *utlsFallbackPath, now time.Time, destination M.Socksaddr, closing string, refusal error) string {
	// counted from the last rest of this kind: a rest for a candidate answered again may
	// have come since
	if path.rest > 0 && now.Sub(path.exhaustedUntil) < path.rest {
		path.rest = min(2*path.rest, utlsFallbackRestMax)
	} else {
		path.rest = utlsFallbackRest
	}
	path.exhaustedUntil = now.Add(path.rest)
	said := F.ToString("ClientHello unanswered with all of ", f.names())
	line := F.ToString("ClientHello to ", destination, " unanswered with all of ", f.names())
	if path.refused > 0 {
		// some were answered, and the handshake failed after that
		counted := F.ToString(" (", path.failed-path.refused, " unanswered, ", path.refused, " refused")
		if refusal != nil {
			counted = F.ToString(counted, "; ", closing, ": ", refusal)
		}
		said = F.ToString("none of ", f.names(), " got through", counted, ")")
		line = F.ToString("none of ", f.names(), " got through to ", destination, counted, ")")
	}
	f.rests(path, now, path.rest)
	kept := f.candidates[path.position].String()
	if path.position == f.configured && path.last < 0 {
		kept += " is used as configured"
	} else {
		kept += " is used: it worked here last"
	}
	f.warn("tls: ", line, f.cause(), "; the fallback rests for ", path.rest, ", ", kept)
	return said + f.cause()
}

// cause is what a line about ClientHellos nobody answered adds when tls.spoof is on.
func (f *utlsFallback) cause() string {
	if f.spoof {
		return "; tls.spoof is enabled and may be the cause"
	}
	return ""
}

// utlsFallbackDial follows one dial: fingerprintDial.
type utlsFallbackDial struct {
	fallback *utlsFallback
	// the server name, a part of the key of the choice
	serverName string
	// configuration returns the configuration of the dial with a candidate
	configuration func(candidate utlsFallbackCandidate) Config
	path          *utlsFallbackPath
	// the candidate of the last attempt, and when its connection was made
	position  int
	connected time.Time
	attempts  int
	// the last attempt is watched: not while the fallback rests
	watched bool
	// which of the watched ClientHellos sent since the last rest it is
	ordinal int
	// this dial tries the candidates while nothing is known (the others wait for it), or
	// tries the first candidate again, the choice being old
	probe   bool
	recheck bool
}

func (d *utlsFallbackDial) ready(ctx context.Context, destination M.Socksaddr) error {
	f := d.fallback
	for {
		f.access.Lock()
		f.load(d.serverName, destination)
		if f.known || time.Now().Before(f.restUntil) {
			f.access.Unlock()
			return nil
		}
		if f.probing == nil {
			f.probing = make(chan struct{})
			d.probe = true
			f.access.Unlock()
			return nil
		}
		probing := f.probing
		f.access.Unlock()
		select {
		case <-probing:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (d *utlsFallbackDial) done() {
	f := d.fallback
	f.access.Lock()
	defer f.access.Unlock()
	if d.probe {
		d.probe = false
		if f.probing != nil {
			close(f.probing)
			f.probing = nil
		}
	}
	if d.recheck {
		d.recheck = false
		d.path.rechecking = false
	}
}

func (d *utlsFallbackDial) attempt(conn net.Conn) (Config, bool) {
	f := d.fallback
	f.access.Lock()
	defer f.access.Unlock()
	if d.path == nil {
		d.path = f.path(conn)
	}
	path := d.path
	d.attempts++
	d.connected = time.Now()
	d.watched = !d.connected.Before(path.restUntil)
	if d.watched && path.resume >= 0 {
		// the first dial after a rest
		path.position, path.resume = path.resume, -1
	}
	d.position = path.position
	if d.watched {
		path.sent++
		d.ordinal = path.sent
		if d.attempts == 1 && path.position != 0 && !path.rechecking && !path.chosen.IsZero() && d.connected.Sub(path.chosen) >= utlsFallbackRecheck {
			// the choice is old: this dial tries the first candidate again, the others go
			// on with the choice
			path.rechecking = true
			d.recheck = true
			d.position = 0
		}
	}
	return d.configuration(f.candidates[d.position]), d.watched
}

// rechecked ends the try of the first candidate again: answered or not, the choice is good
// for another utlsFallbackRecheck. The caller holds the lock.
func (d *utlsFallbackDial) rechecked(path *utlsFallbackPath, now time.Time, answered bool) {
	f := d.fallback
	d.recheck = false
	path.rechecking = false
	if answered {
		path.position = 0
		path.worked |= 1
		path.last = 0
		path.failed, path.refused = 0, 0
		path.suspected = time.Time{}
		f.warn("tls: ", f.candidates[0], " is answered again; it is used from now on")
	}
	f.known = true
	f.store(path, now)
}

func (d *utlsFallbackDial) answered() {
	f := d.fallback
	f.access.Lock()
	defer f.access.Unlock()
	path := d.path
	now := time.Now()
	if d.recheck {
		d.rechecked(path, now, true)
		return
	}
	// of a dial that began with a candidate the path has left
	if d.position != path.position {
		return
	}
	first := path.worked&(1<<d.position) == 0
	path.worked |= 1 << d.position
	path.last = d.position
	f.known = true
	if first || f.saved != d.position || now.Sub(path.chosen) >= utlsFallbackRecheck {
		f.store(path, now)
	}
	if !d.watched || now.Before(path.restUntil) {
		return
	}
	name := f.candidates[d.position].String()
	if !path.suspected.IsZero() {
		// On this or on another connection: what left the other ClientHello unanswered did
		// not do so for the ClientHello alone.
		path.again++
		f.rests(path, now, utlsFallbackRest)
		f.warn("tls: ", name, " is answered after its ClientHello was not: a loss on the way, or something that does not choose by the ClientHello; the fallback rests for ", utlsFallbackRest)
		return
	}
	path.failed, path.refused = 0, 0
	if first && d.position != 0 {
		f.warn("tls: ", name, " is answered where ", f.candidates[0], " was not; it is used from now on")
	} else if first {
		f.logger.Info("tls: ", name, " is answered; it is used")
	}
}

func (d *utlsFallbackDial) unanswered(destination M.Socksaddr) (bool, error) {
	f := d.fallback
	f.access.Lock()
	defer f.access.Unlock()
	path := d.path
	last := f.candidates[d.position].String()
	now := time.Now()
	if d.recheck {
		// the first candidate is still not let through: the dial goes on with the choice
		d.rechecked(path, now, false)
		return true, nil
	}
	if !d.watched || now.Before(path.restUntil) {
		// another dial has put the fallback to rest meanwhile
		return false, E.New("ClientHello unanswered with ", last)
	}
	// another dial may have moved on already
	if path.position == d.position {
		if path.suspected.IsZero() && (d.ordinal > utlsFallbackFirst || now.Sub(path.restUntil) > utlsFallbackQuiet) {
			// not soon after the last rest: a row of them begins anew
			path.again = 0
		}
		if path.twice() && path.again < utlsFallbackAgain && (path.suspected.IsZero() || !d.connected.After(path.suspected)) {
			// the first time, or of a connection made before that
			if path.suspected.IsZero() {
				path.suspected = now
			}
			if d.attempts >= utlsFallbackAttempts {
				f.warn("tls: ClientHello to ", destination, " unanswered with ", last, ", the next connection tries it once more")
				return false, E.New("ClientHello unanswered with ", last)
			}
			f.warn("tls: ClientHello to ", destination, " unanswered with ", last, ", trying it once more")
			return true, nil
		}
		f.advance(path)
	}
	if path.failed >= len(f.candidates) {
		return false, E.New(f.exhausted(path, now, destination, last, nil))
	}
	next := f.candidates[path.position].String()
	if d.attempts >= utlsFallbackAttempts {
		f.warn("tls: ClientHello to ", destination, " unanswered with ", last, ", the next connection tries ", next)
		return false, E.New("ClientHello unanswered with ", last)
	}
	f.warn("tls: ClientHello to ", destination, " unanswered with ", last, ", retrying with ", next)
	return true, nil
}

func (d *utlsFallbackDial) failed(ctx context.Context, destination M.Socksaddr, err error) bool {
	f := d.fallback
	f.access.Lock()
	defer f.access.Unlock()
	path := d.path
	now := time.Now()
	var stranger *realityStrangerError
	refused := errors.As(err, &stranger)
	if d.recheck && ctx.Err() == nil {
		// what the first candidate met, the choice is kept: the dial goes on with it
		d.rechecked(path, now, false)
		return true
	}
	// a dial its caller has given up tells nothing of the ClientHello
	if !d.watched || ctx.Err() != nil || d.position != path.position || now.Before(path.restUntil) {
		return false
	}
	if !refused && path.twice() {
		// answered, with a failure of another kind: not what the fallback is for
		path.suspected = time.Time{}
		return false
	}
	// A server that answers the ClientHello as a stranger's takes none of its kind (a
	// REALITY server since Xray-core v26.9.8 and a ClientHello without the X25519MLKEM768
	// key share): left at once, whatever worked before the server was updated. A candidate
	// that has not completed a handshake here is no better than the one it replaced when
	// its handshake fails in any way: one the server cannot carry would otherwise stay in
	// use for good.
	path.worked &^= 1 << d.position
	if path.last == d.position {
		path.last = -1
	}
	last := f.candidates[d.position].String()
	f.advance(path)
	path.refused++
	if path.failed >= len(f.candidates) {
		f.exhausted(path, now, destination, last, err)
		return false
	}
	next := f.candidates[path.position].String()
	why := F.ToString("failed with ", last, " (", err, ")")
	if refused {
		why = F.ToString("refused ", last, ", as a REALITY server since Xray-core v26.9.8 does")
	}
	// after a handshake that waited out its whole time the dial is not made longer still
	late := errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded)
	if d.attempts >= utlsFallbackAttempts || late {
		f.warn("tls: the handshake with ", destination, " ", why, ", the next connection tries ", next)
		return false
	}
	f.warn("tls: the handshake with ", destination, " ", why, ", retrying with ", next)
	return true
}

func (c *UTLSClientConfig) fingerprintDial() fingerprintDial {
	if c.fallback == nil {
		return nil
	}
	return &utlsFallbackDial{
		fallback:   c.fallback,
		serverName: c.ServerName(),
		configuration: func(candidate utlsFallbackCandidate) Config {
			attempt := *c
			attempt.id = candidate.id
			attempt.noMLKEM = candidate.noMLKEM
			return &attempt
		},
	}
}

func (e *RealityClientConfig) fingerprintDial() fingerprintDial {
	f := e.uClient.fallback
	if f == nil {
		return nil
	}
	return &utlsFallbackDial{
		fallback:   f,
		serverName: e.uClient.ServerName(),
		configuration: func(candidate utlsFallbackCandidate) Config {
			uClient := *e.uClient
			uClient.id = candidate.id
			uClient.noMLKEM = candidate.noMLKEM
			attempt := *e
			attempt.uClient = &uClient
			// A ClientHello without the key share REALITY servers ask for since Xray-core
			// v26.9.8 is tried as any other: an older server takes it, and what a newer one
			// answers names it and moves the fallback on.
			classic := candidate.noMLKEM || utlsClassicFingerprint(candidate.name)
			attempt.classicFingerprint = ""
			if classic {
				attempt.classicFingerprint = candidate.String()
			}
			attempt.classicFallback = classic
			return &attempt
		},
	}
}

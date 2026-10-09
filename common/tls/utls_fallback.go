//go:build with_utls

package tls

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

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
	// local addresses whose fingerprint is remembered
	utlsFallbackPaths = 8
	// The list of a fallback that is turned on without one. First the two whose
	// ClientHello carries no ECH extension; then one whose ClientHello is small (no
	// X25519MLKEM768 key share, a single segment), for a path that drops the large ones.
	// A REALITY server older than Xray-core v26.9.8 takes that one as any other; a newer
	// one refuses it, and the fallback goes on with the next.
	utlsFallbackDefaultOrder = "safari,randomized,edge,firefox,chrome"
	// lines remembered so as not to be repeated
	utlsFallbackLines = 64
	// fingerprints of a list: one bit each in what a path remembers
	utlsFallbackCandidates = 32
	// times in a row a fingerprint may be answered again after it was not, before the
	// next time counts against it
	utlsFallbackAgain = 3
	// such a time is one of a row when the ClientHello that went unanswered was among
	// this many first ones sent since the rest before it ended
	utlsFallbackFirst = 10
)

var (
	utlsFallbackOrder   = os.Getenv("SING_BOX_UTLS_FALLBACK")
	utlsFallbackWarning sync.Once
	// a line that comes again within this time is counted, not written
	utlsFallbackLogInterval = 10 * time.Second
	// The fallback of a path rests when what leaves a ClientHello unanswered turns out
	// not to choose by fingerprint: every fingerprint of the list went unanswered (a block
	// of the address or of the name, a limit on the number of connections, a server that
	// is down), or the one that went unanswered is answered on another connection (a loss
	// on the way). Another fingerprint does not help there, and every further try is one
	// more connection. While the fallback rests, connections are made exactly as without
	// it, with the fingerprint that worked last. The rest after the whole list is twice
	// as long when the next one begins as soon after it, up to the maximum.
	utlsFallbackRest    = 30 * time.Second
	utlsFallbackRestMax = 10 * time.Minute
	// without a ClientHello left unanswered for this long, what was before is forgotten
	utlsFallbackQuiet = 5 * time.Minute
)

type utlsFallbackCandidate struct {
	name string
	id   utls.ClientHelloID
}

// utlsFallbackPath is what the fallback has learned from one local address.
//
// A path begins with the configured fingerprint. A fingerprint is left for the next of
// the list when its ClientHello goes unanswered; the configured one, and one that has
// completed a handshake on this path, only when that happens on two connections in a row,
// the second made after the first was given up: one unanswered ClientHello may be a second
// of loss, while a new connection is made over a path that has just carried its SYN.
// When such a fingerprint is answered after all, the fallback rests (see above); after
// utlsFallbackAgain such rests in a row the next unanswered ClientHello counts at once:
// what drops a part of the ClientHellos of one fingerprint looks like a loss each time.
// The rests are in a row when the ClientHello that began each was among the first
// utlsFallbackFirst sent since the rest before it: a filter that drops one fingerprint
// in twenty or more does that as a rule, a loss of one ClientHello in a hundred seldom.
// A fingerprint of the list that a REALITY server has taken and then answers as a
// stranger's (failed) is from then on as one that has not completed a handshake here.
type utlsFallbackPath struct {
	local netip.Addr
	// the candidate in use
	position int
	// candidates left in a row, and of them those that the server answered and refused
	failed  int
	refused int
	// the candidates that have completed a handshake on this path, a bit each, and the
	// one that did last; a candidate that has been answered as a stranger's since is in
	// neither
	worked uint64
	last   int
	// when the ClientHello of the candidate in use went unanswered for the first time
	suspected time.Time
	// rests in a row that the candidate in use began by being answered again, and the
	// ClientHellos sent with it and watched since the last of them ended
	again int
	sent  int
	// until when the fallback rests
	restUntil time.Time
	// the last rest after a whole list: how long it was, and when it ended
	rest           time.Duration
	exhaustedUntil time.Time
}

// twice tells whether the candidate in use is left only after two unanswered
// connections: the configured one and one that has worked here.
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
	// the configured fingerprint first
	candidates []utlsFallbackCandidate
	// with tls.spoof the forged ClientHello may be what the path does not let through: the
	// lines say so
	spoof  bool
	access sync.Mutex
	paths  []*utlsFallbackPath
	lines  map[string]*utlsFallbackLine
}

// utlsFallbackList tells which fingerprints the fallback goes through, and from where
// the list is. The option experimental.utls_fallback of the configuration decides when
// it is there: off, or on with its fingerprints, or with the default ones when it names
// none. A configuration without the option leaves it to the environment
// (SING_BOX_UTLS_FALLBACK). An empty list is no fallback.
func utlsFallbackList(ctx context.Context) (string, string) {
	configured := service.FromContext[*option.UTLSFallbackOptions](ctx)
	if configured == nil {
		return utlsFallbackOrder, "SING_BOX_UTLS_FALLBACK"
	}
	if !configured.Enabled {
		return "", ""
	}
	order := strings.Join(configured.Fingerprints, ",")
	if strings.Trim(order, ", \t") == "" {
		// a list that names nothing ("", [""]) is no list
		order = utlsFallbackDefaultOrder
	}
	return order, "experimental.utls_fallback.fingerprints"
}

// newUTLSFallback makes the fallback of a client with the fingerprint configured (of the
// ID configuredID), nil when it is off: turned off or not turned on (utlsFallbackList), a
// list with a name that is not a fingerprint, or nothing in it to go on with. For REALITY
// the fingerprints it cannot work with are left out; the ones that only older servers take
// are tried as the rest.
func newUTLSFallback(ctx context.Context, logger logger.ContextLogger, configured string, configuredID utls.ClientHelloID, reality bool, spoof bool) *utlsFallback {
	order, source := utlsFallbackList(ctx)
	if order == "" {
		return nil
	}
	if logger == nil {
		logger = log.StdLogger()
	}
	if configured == "" {
		configured = "chrome"
	}
	candidates := []utlsFallbackCandidate{{configured, configuredID}}
	for _, name := range strings.Split(order, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		id, err := uTLSClientHelloID(name)
		if err != nil {
			utlsFallbackWarning.Do(func() {
				logger.Warn(source, ": ", name, " is not a uTLS fingerprint, the fingerprint fallback is off")
			})
			return nil
		}
		if reality {
			_, unsupported := checkRealityFingerprint(name)
			if unsupported != nil {
				continue
			}
		}
		known := false
		for _, candidate := range candidates {
			if candidate.id == id {
				known = true
				break
			}
		}
		if !known && len(candidates) < utlsFallbackCandidates {
			candidates = append(candidates, utlsFallbackCandidate{name, id})
		}
	}
	if len(candidates) < 2 {
		return nil
	}
	return &utlsFallback{logger: logger, candidates: candidates, spoof: spoof, lines: make(map[string]*utlsFallbackLine)}
}

// warn writes a line of the fallback, once in utlsFallbackLogInterval: a path that
// answers no ClientHello gives the same lines on every connection. The next time the
// line is written it says how many times it came meanwhile. The caller holds the lock.
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
	path := &utlsFallbackPath{local: local}
	if len(f.paths) < utlsFallbackPaths {
		f.paths = append(f.paths, nil)
	}
	copy(f.paths[1:], f.paths)
	f.paths[0] = path
	return path
}

func (f *utlsFallback) names() string {
	names := make([]string, 0, len(f.candidates))
	for _, candidate := range f.candidates {
		names = append(names, candidate.name)
	}
	return strings.Join(names, ", ")
}

// advance takes the next candidate of a path. The caller holds the lock.
func (f *utlsFallback) advance(path *utlsFallbackPath) {
	path.position = (path.position + 1) % len(f.candidates)
	path.failed++
	path.suspected = time.Time{}
	path.again, path.sent = 0, 0
}

// rests puts the fallback of a path to rest for the given time, on the candidate that
// completed a handshake last, the configured one when none is remembered: its
// connections are made as without the fallback. The caller holds the lock.
func (f *utlsFallback) rests(path *utlsFallbackPath, now time.Time, rest time.Duration) {
	path.restUntil = now.Add(rest)
	path.position = path.last
	path.failed, path.refused = 0, 0
	path.suspected = time.Time{}
	path.sent = 0
}

// exhausted is the verdict of a list that was gone through without one handshake: the
// fallback rests, twice as long as the last time when that was not long ago. refusal is
// the failure of the candidate that closed the list, nil when its ClientHello went
// unanswered. It returns what the dial says of it. The caller holds the lock.
func (f *utlsFallback) exhausted(path *utlsFallbackPath, now time.Time, destination M.Socksaddr, closing string, refusal error) string {
	// counted from the last rest of this kind: a rest for a fingerprint answered again
	// may have come since
	if path.rest > 0 && now.Sub(path.exhaustedUntil) < path.rest {
		path.rest = min(2*path.rest, utlsFallbackRestMax)
	} else {
		path.rest = utlsFallbackRest
	}
	path.exhaustedUntil = now.Add(path.rest)
	said := F.ToString("ClientHello unanswered with all fingerprints (", f.names(), ")")
	line := F.ToString("ClientHello to ", destination, " unanswered with all fingerprints (", f.names(), ")")
	if path.refused > 0 {
		// some were answered, and the handshake failed after that
		counted := F.ToString(" (", path.failed-path.refused, " unanswered, ", path.refused, " refused")
		if refusal != nil {
			counted = F.ToString(counted, "; ", closing, ": ", refusal)
		}
		said = F.ToString("no fingerprint of ", f.names(), " got through", counted, ")")
		line = F.ToString("no fingerprint of ", f.names(), " got through to ", destination, counted, ")")
	}
	f.rests(path, now, path.rest)
	kept := f.candidates[path.position].name
	if path.position == 0 {
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
	// configuration returns the configuration of the dial with the fingerprint of a
	// candidate
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
}

func (d *utlsFallbackDial) attempt(conn net.Conn) (Config, bool) {
	f := d.fallback
	f.access.Lock()
	defer f.access.Unlock()
	if d.path == nil {
		d.path = f.path(conn)
	}
	d.attempts++
	d.connected = time.Now()
	d.position = d.path.position
	d.watched = !d.connected.Before(d.path.restUntil)
	if d.watched {
		d.path.sent++
		d.ordinal = d.path.sent
	}
	return d.configuration(f.candidates[d.position]), d.watched
}

func (d *utlsFallbackDial) answered() {
	f := d.fallback
	f.access.Lock()
	defer f.access.Unlock()
	path := d.path
	now := time.Now()
	// of a dial that began with a candidate the path has left
	if d.position != path.position {
		return
	}
	first := path.worked&(1<<d.position) == 0
	path.worked |= 1 << d.position
	path.last = d.position
	if !d.watched || now.Before(path.restUntil) {
		return
	}
	name := f.candidates[d.position].name
	if !path.suspected.IsZero() {
		// On this or on another connection: what left the other ClientHello unanswered
		// did not do so for the fingerprint alone.
		path.again++
		f.rests(path, now, utlsFallbackRest)
		f.warn("tls: fingerprint ", name, " is answered after its ClientHello was not: a loss on the way, or something that does not choose by fingerprint; the fallback rests for ", utlsFallbackRest)
		return
	}
	path.failed, path.refused = 0, 0
	if first && d.position != 0 {
		f.warn("tls: fingerprint ", name, " is answered where ", f.candidates[0].name, " was not; it is used from now on")
	}
}

func (d *utlsFallbackDial) unanswered(destination M.Socksaddr) (bool, error) {
	f := d.fallback
	f.access.Lock()
	defer f.access.Unlock()
	path := d.path
	last := f.candidates[d.position].name
	now := time.Now()
	if !d.watched || now.Before(path.restUntil) {
		// another dial has put the fallback to rest meanwhile
		return false, E.New("ClientHello unanswered with fingerprint ", last)
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
				f.warn("tls: ClientHello to ", destination, " unanswered with fingerprint ", last, ", the next connection tries it once more")
				return false, E.New("ClientHello unanswered with fingerprint ", last)
			}
			f.warn("tls: ClientHello to ", destination, " unanswered with fingerprint ", last, ", trying it once more")
			return true, nil
		}
		f.advance(path)
	}
	if path.failed >= len(f.candidates) {
		return false, E.New(f.exhausted(path, now, destination, last, nil))
	}
	next := f.candidates[path.position].name
	if d.attempts >= utlsFallbackAttempts {
		f.warn("tls: ClientHello to ", destination, " unanswered with fingerprint ", last, ", the next connection tries ", next)
		return false, E.New("ClientHello unanswered with fingerprint ", last)
	}
	f.warn("tls: ClientHello to ", destination, " unanswered with fingerprint ", last, ", retrying with ", next)
	return true, nil
}

func (d *utlsFallbackDial) failed(ctx context.Context, destination M.Socksaddr, err error) bool {
	f := d.fallback
	f.access.Lock()
	defer f.access.Unlock()
	path := d.path
	now := time.Now()
	// a dial its caller has given up tells nothing of the fingerprint
	if !d.watched || ctx.Err() != nil || d.position != path.position || now.Before(path.restUntil) {
		return false
	}
	var stranger *realityStrangerError
	if path.twice() && (d.position == 0 || !errors.As(err, &stranger)) {
		// answered, with a refusal: not what the fallback is for
		path.suspected = time.Time{}
		return false
	}
	// A fingerprint the fallback has gone on to and that has not completed a handshake
	// here is no better than the one it replaced when its handshake fails, whatever the
	// failure: one that the server answers and refuses (ECH that it cannot carry, a
	// version of TLS the server does not speak) would otherwise stay in use for good.
	// So would one without the key share REALITY servers ask for since Xray-core v26.9.8
	// that has worked here, when the server is updated: it is answered as a stranger from
	// then on, and is as one that has not worked.
	path.worked &^= 1 << d.position
	if path.last == d.position {
		path.last = 0
	}
	last := f.candidates[d.position].name
	f.advance(path)
	path.refused++
	if path.failed >= len(f.candidates) {
		f.exhausted(path, now, destination, last, err)
		return false
	}
	next := f.candidates[path.position].name
	// after a handshake that waited out its whole time the dial is not made longer still
	late := errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded)
	if d.attempts >= utlsFallbackAttempts || late {
		f.warn("tls: the handshake with ", destination, " failed with fingerprint ", last, " (", err, "), the next connection tries ", next)
		return false
	}
	f.warn("tls: the handshake with ", destination, " failed with fingerprint ", last, " (", err, "), retrying with ", next)
	return true
}

func (c *UTLSClientConfig) fingerprintDial() fingerprintDial {
	if c.fallback == nil {
		return nil
	}
	return &utlsFallbackDial{
		fallback: c.fallback,
		configuration: func(candidate utlsFallbackCandidate) Config {
			attempt := *c
			attempt.id = candidate.id
			return &attempt
		},
	}
}

func (e *RealityClientConfig) fingerprintDial() fingerprintDial {
	if e.uClient.fallback == nil {
		return nil
	}
	return &utlsFallbackDial{
		fallback: e.uClient.fallback,
		configuration: func(candidate utlsFallbackCandidate) Config {
			uClient := *e.uClient
			uClient.id = candidate.id
			attempt := *e
			attempt.uClient = &uClient
			if candidate.id != e.uClient.id {
				// A fingerprint of the list. One without the key share REALITY servers ask
				// for since Xray-core v26.9.8 is tried as any other: an older server takes
				// it, and what a newer one answers names it.
				classic, _ := checkRealityFingerprint(candidate.name)
				attempt.classicFingerprint = ""
				if classic {
					attempt.classicFingerprint = candidate.name
				}
				attempt.classicFallback = classic
			}
			return &attempt
		},
	}
}

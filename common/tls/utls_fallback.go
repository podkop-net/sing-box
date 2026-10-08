//go:build with_utls

package tls

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	utls "github.com/metacubex/utls"
)

const (
	// handshakes of one dial; the next dial goes on with the list
	utlsFallbackAttempts = 3
	// local addresses whose fingerprint is remembered
	utlsFallbackPaths = 8
)

var (
	utlsFallbackOrder   = os.Getenv("SING_BOX_UTLS_FALLBACK")
	utlsFallbackWarning sync.Once
)

type utlsFallbackCandidate struct {
	name string
	id   utls.ClientHelloID
}

// utlsFallbackPath is what the fallback has learned from one local address.
type utlsFallbackPath struct {
	local netip.Addr
	// the candidate in use
	position int
	// candidates in a row whose ClientHello got no acknowledgment
	failed int
	// the candidate reported as the one that works, plus one
	reported int
}

// utlsFallback is shared by a client configuration and its clones.
type utlsFallback struct {
	logger logger.ContextLogger
	// the configured fingerprint first
	candidates []utlsFallbackCandidate
	// with tls.spoof nothing is remembered: the forged ClientHello may be what the
	// path does not let through, and then no fingerprint is the one that works
	spoof  bool
	access sync.Mutex
	paths  []*utlsFallbackPath
}

// newUTLSFallback makes the fallback of a client with the fingerprint configured (of the
// ID configuredID), nil when it is off: no list in the environment, a list with a name
// that is not a fingerprint, or nothing in it to go on with. For REALITY the fingerprints
// it does not work with, or only with older servers, are left out.
func newUTLSFallback(logger logger.ContextLogger, configured string, configuredID utls.ClientHelloID, reality bool, spoof bool) *utlsFallback {
	if utlsFallbackOrder == "" {
		return nil
	}
	if logger == nil {
		logger = log.StdLogger()
	}
	if configured == "" {
		configured = "chrome"
	}
	candidates := []utlsFallbackCandidate{{configured, configuredID}}
	for _, name := range strings.Split(utlsFallbackOrder, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		id, err := uTLSClientHelloID(name)
		if err != nil {
			utlsFallbackWarning.Do(func() {
				logger.Warn("SING_BOX_UTLS_FALLBACK: ", name, " is not a uTLS fingerprint, the fingerprint fallback is off")
			})
			return nil
		}
		if reality {
			classic, err := checkRealityFingerprint(name)
			if err != nil || classic {
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
		if !known {
			candidates = append(candidates, utlsFallbackCandidate{name, id})
		}
	}
	if len(candidates) < 2 {
		return nil
	}
	return &utlsFallback{logger: logger, candidates: candidates, spoof: spoof}
}

// path returns what is known of the local address of conn. The caller holds the lock.
func (f *utlsFallback) path(conn net.Conn) *utlsFallbackPath {
	local := M.AddrPortFromNet(conn.LocalAddr()).Addr().Unmap().WithZone("")
	if f.spoof {
		return &utlsFallbackPath{local: local}
	}
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

// utlsFallbackDial follows one dial: fingerprintDial.
type utlsFallbackDial struct {
	fallback *utlsFallback
	// configuration returns the configuration of the dial with another fingerprint
	configuration func(id utls.ClientHelloID) Config
	path          *utlsFallbackPath
	// the candidate of the last attempt
	position int
	attempts int
}

func (d *utlsFallbackDial) attempt(conn net.Conn) Config {
	f := d.fallback
	f.access.Lock()
	if d.path == nil {
		d.path = f.path(conn)
	}
	d.position = d.path.position
	f.access.Unlock()
	d.attempts++
	return d.configuration(f.candidates[d.position].id)
}

func (d *utlsFallbackDial) answered() {
	f := d.fallback
	f.access.Lock()
	defer f.access.Unlock()
	if d.path.position != d.position {
		return
	}
	d.path.failed = 0
	if d.position != 0 && d.path.reported != d.position+1 && !f.spoof {
		d.path.reported = d.position + 1
		f.logger.Warn("tls: fingerprint ", f.candidates[d.position].name, " is answered where ", f.candidates[0].name, " was not; it is used from now on")
	}
}

func (d *utlsFallbackDial) unanswered(destination M.Socksaddr) (bool, error) {
	f := d.fallback
	f.access.Lock()
	defer f.access.Unlock()
	last := f.candidates[d.position].name
	// another dial may have moved on already
	if d.path.position == d.position {
		d.path.position = (d.position + 1) % len(f.candidates)
		d.path.failed++
	}
	if d.path.failed >= len(f.candidates) {
		d.path.failed = 0
		note := ""
		if f.spoof {
			note = "; tls.spoof is enabled and may be the cause"
		}
		f.logger.Warn("tls: ClientHello to ", destination, " unanswered with all fingerprints (", f.names(), ")", note)
		return false, E.New("ClientHello unanswered with all fingerprints (", f.names(), ")", note)
	}
	next := f.candidates[d.path.position].name
	if d.attempts >= utlsFallbackAttempts {
		if f.spoof {
			f.logger.Warn("tls: ClientHello to ", destination, " unanswered with fingerprint ", last, " and the ones before it; tls.spoof is enabled and may be the cause")
		} else {
			f.logger.Warn("tls: ClientHello to ", destination, " unanswered with fingerprint ", last, ", the next connection tries ", next)
		}
		return false, E.New("ClientHello unanswered with fingerprint ", last)
	}
	f.logger.Warn("tls: ClientHello to ", destination, " unanswered with fingerprint ", last, ", retrying with ", next)
	return true, nil
}

func (c *UTLSClientConfig) fingerprintDial() fingerprintDial {
	if c.fallback == nil {
		return nil
	}
	return &utlsFallbackDial{
		fallback: c.fallback,
		configuration: func(id utls.ClientHelloID) Config {
			attempt := *c
			attempt.id = id
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
		configuration: func(id utls.ClientHelloID) Config {
			uClient := *e.uClient
			uClient.id = id
			attempt := *e
			attempt.uClient = &uClient
			if id != e.uClient.id {
				// the fingerprints of the list carry the key share REALITY asks for
				attempt.classicFingerprint = ""
			}
			return &attempt
		},
	}
}

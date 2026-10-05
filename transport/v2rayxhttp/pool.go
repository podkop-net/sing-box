package v2rayxhttp

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

const (
	// connectionIdleTimeout closes a pooled connection no request has used for
	// this long (Xray's net.ConnIdleTimeout).
	connectionIdleTimeout = 300 * time.Second
	// chromeH2KeepAlivePeriod is the HTTP/2 ping interval of an idle connection
	// (Xray's net.ChromeH2KeepAlivePeriod).
	chromeH2KeepAlivePeriod = 45 * time.Second

	// A pooled connection that fails before it has lived youngConnection is
	// counted against the server: after the second such failure in a row new
	// connections wait, longer each time, up to maxBackoff. A server or CDN that
	// resets every stream would otherwise be redialled as fast as the clients
	// reconnect, a TLS handshake each time.
	youngConnection = 5 * time.Second
	failureMemory   = 30 * time.Second
	firstBackoff    = 250 * time.Millisecond
	maxBackoff      = 5 * time.Second
)

// pooledConnection is one HTTP connection of the pool (for HTTP/1.1 a few, see
// http1Connection): every request of a session that took it goes through it.
type pooledConnection interface {
	roundTrip(request *http.Request) (*http.Response, error)
	// close tears the connection down, requests in flight included.
	close()
}

type pool struct {
	newConnection func() pooledConnection
	config        xmuxConfig
	idleTimeout   time.Duration
	concurrency   int32
	connections   int32

	access   sync.Mutex
	clients  []*poolClient
	closed   bool
	failures int
	lastFail time.Time
	retryAt  time.Time
	lastErr  error
}

func newPool(config xmuxConfig, newConnection func() pooledConnection) *pool {
	return &pool{
		newConnection: newConnection,
		config:        config,
		idleTimeout:   poolIdleTimeout,
		concurrency:   config.maxConcurrency.rand(),
		connections:   config.maxConnections.rand(),
	}
}

// poolClient is a pooled connection with its XMUX budget. running counts the
// sessions and upload requests using it: a client taken out of the pool is
// closed once the last of them is done.
type poolClient struct {
	pool         *pool
	connection   pooledConnection
	createdAt    time.Time
	running      atomic.Int32
	leftUsage    int32 // under pool.access; -1 is no limit
	leftRequests atomic.Int32
	unreusableAt time.Time
	broken       atomic.Bool
	removed      atomic.Bool
	closeOnce    sync.Once
	// idleGeneration changes whenever the client is taken, so that a check
	// scheduled when it went idle knows whether it stayed idle.
	idleGeneration atomic.Uint64
}

// poolIdleTimeout retires a pooled connection no session has used for this
// long. HTTP/3 needs it: the QUIC keep-alive keeps an idle connection open
// for good (Xray keeps it until XMUX retires it, 30 to 50 minutes on).
var poolIdleTimeout = connectionIdleTimeout

// get returns a client for a new session (or for the next upload request of
// one) and counts it as running; release gives it back.
func (p *pool) get() (*poolClient, error) {
	p.access.Lock()
	defer p.access.Unlock()
	if p.closed {
		return nil, net.ErrClosed
	}
	now := time.Now()
	for i := 0; i < len(p.clients); {
		client := p.clients[i]
		if client.broken.Load() || client.leftUsage == 0 || client.leftRequests.Load() <= 0 ||
			(!client.unreusableAt.IsZero() && now.After(client.unreusableAt)) {
			client.removed.Store(true)
			client.closeIfIdle()
			p.clients = append(p.clients[:i], p.clients[i+1:]...)
		} else {
			i++
		}
	}
	var client *poolClient
	switch {
	case len(p.clients) == 0, p.connections > 0 && len(p.clients) < int(p.connections):
	default:
		candidates := p.clients
		if p.concurrency > 0 {
			candidates = make([]*poolClient, 0, len(p.clients))
			for _, candidate := range p.clients {
				if candidate.running.Load() < p.concurrency {
					candidates = append(candidates, candidate)
				}
			}
		}
		if len(candidates) > 0 {
			client = candidates[rand.IntN(len(candidates))]
			if client.leftUsage > 0 {
				client.leftUsage--
			}
		}
	}
	if client == nil {
		if now.Before(p.retryAt) {
			return nil, E.Cause(p.lastErr, "xhttp: server failed ", p.failures, " connections in a row, next try in ", p.retryAt.Sub(now).Round(time.Millisecond))
		}
		client = p.newClient(now)
	}
	client.acquire()
	return client, nil
}

// acquire counts one more user of the client; release ends it.
func (c *poolClient) acquire() {
	c.running.Add(1)
	c.idleGeneration.Add(1)
}

func (p *pool) newClient(now time.Time) *poolClient {
	client := &poolClient{
		pool:       p,
		connection: p.newConnection(),
		createdAt:  now,
		leftUsage:  -1,
	}
	if usage := p.config.cMaxReuseTimes.rand(); usage > 0 {
		client.leftUsage = usage - 1
	}
	client.leftRequests.Store(math.MaxInt32)
	if requests := p.config.hMaxRequestTimes.rand(); requests > 0 {
		client.leftRequests.Store(requests)
	}
	if seconds := p.config.hMaxReusableSecs.rand(); seconds > 0 {
		client.unreusableAt = now.Add(time.Duration(seconds) * time.Second)
	}
	p.clients = append(p.clients, client)
	return client
}

// usable tells whether a session holding the client may still send requests
// through it (packet-up moves its uploads to another client when not).
func (c *poolClient) usable() bool {
	return !c.broken.Load() && c.leftRequests.Load() > 0 &&
		(c.unreusableAt.IsZero() || time.Now().Before(c.unreusableAt))
}

func (c *poolClient) roundTrip(request *http.Request) (*http.Response, error) {
	c.leftRequests.Add(-1)
	response, err := c.connection.roundTrip(request)
	if err != nil {
		c.fail(request.Context(), err)
	}
	return response, err
}

// fail takes the client out of service after a failed request, as Xray does.
// A request we cancelled ourselves (a session closed, a dial given up) says
// nothing about the server.
func (c *poolClient) fail(ctx context.Context, err error) {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return
	}
	if c.broken.Swap(true) {
		return
	}
	c.pool.noteFailure(c, err)
}

func (p *pool) noteFailure(client *poolClient, err error) {
	p.access.Lock()
	defer p.access.Unlock()
	now := time.Now()
	if now.Sub(client.createdAt) >= youngConnection || now.Sub(p.lastFail) >= failureMemory {
		p.failures = 0
	}
	if now.Sub(client.createdAt) < youngConnection {
		p.failures++
	}
	p.lastFail = now
	p.lastErr = err
	if p.failures >= 2 {
		backoff := firstBackoff << min(p.failures-2, 5)
		p.retryAt = now.Add(min(backoff, maxBackoff))
	}
}

func (c *poolClient) release() {
	if c.running.Add(-1) > 0 {
		return
	}
	if c.removed.Load() {
		c.closeIfIdle()
		return
	}
	generation := c.idleGeneration.Load()
	time.AfterFunc(c.pool.idleTimeout, func() {
		if c.running.Load() <= 0 && c.idleGeneration.Load() == generation {
			c.pool.retire(c)
		}
	})
}

// retire takes an idle client out of the pool and closes it.
func (p *pool) retire(client *poolClient) {
	p.access.Lock()
	for i, candidate := range p.clients {
		if candidate == client {
			p.clients = append(p.clients[:i], p.clients[i+1:]...)
			break
		}
	}
	p.access.Unlock()
	client.removed.Store(true)
	client.closeIfIdle()
}

func (c *poolClient) closeIfIdle() {
	if c.removed.Load() && c.running.Load() <= 0 {
		c.closeOnce.Do(c.connection.close)
	}
}

func (p *pool) close() {
	p.access.Lock()
	clients := p.clients
	p.clients = nil
	p.closed = true
	p.access.Unlock()
	for _, client := range clients {
		client.removed.Store(true)
		client.closeOnce.Do(client.connection.close)
	}
}

// connTracker remembers the connections a pooled connection dialed, so that it
// can close them all: the HTTP transports close only idle connections on
// request, and a pooled connection taken out of service must not keep its
// sockets until the idle timeout.
type connTracker struct {
	access sync.Mutex
	conns  map[*trackedConn]struct{}
	closed bool
}

type trackedConn struct {
	net.Conn
	tracker *connTracker
}

func (t *connTracker) track(conn net.Conn, err error) (net.Conn, error) {
	if err != nil {
		return nil, err
	}
	t.access.Lock()
	defer t.access.Unlock()
	if t.closed {
		conn.Close()
		return nil, net.ErrClosed
	}
	if t.conns == nil {
		t.conns = make(map[*trackedConn]struct{})
	}
	tracked := &trackedConn{Conn: conn, tracker: t}
	t.conns[tracked] = struct{}{}
	return tracked, nil
}

func (t *connTracker) closeAll() {
	t.access.Lock()
	conns := t.conns
	t.conns = nil
	t.closed = true
	t.access.Unlock()
	for conn := range conns {
		conn.Conn.Close()
	}
}

func (c *trackedConn) Close() error {
	c.tracker.access.Lock()
	delete(c.tracker.conns, c)
	c.tracker.access.Unlock()
	return c.Conn.Close()
}

func (c *trackedConn) Upstream() any {
	return c.Conn
}

// http2Connection carries every request of its sessions as streams of one
// HTTP/2 connection (one per pooled connection, as Xray's XMUX does).
type http2Connection struct {
	transport *http2.Transport
	tracker   connTracker
}

func newHTTP2Connection(tlsDialer tls.Dialer, serverAddr M.Socksaddr, keepAlivePeriod time.Duration) *http2Connection {
	connection := &http2Connection{}
	connection.transport = &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.STDConfig) (net.Conn, error) {
			conn, err := tlsDialer.DialTLSContext(ctx, serverAddr)
			if err != nil {
				return nil, err
			}
			return connection.tracker.track(&frameSizeCapConn{Conn: conn}, nil)
		},
		ReadIdleTimeout: keepAlivePeriod,
		IdleConnTimeout: connectionIdleTimeout,
	}
	return connection
}

func (c *http2Connection) roundTrip(request *http.Request) (*http.Response, error) {
	return c.transport.RoundTrip(request)
}

func (c *http2Connection) close() {
	c.transport.CloseIdleConnections()
	c.tracker.closeAll()
}

// http1Connection is the HTTP/1.1 form: a stream (a download or a streamed
// upload) takes a connection of its own, as with Xray, whose client turns
// keep-alives off for them. Packet-up uploads reuse connections and, unlike
// Xray's raw pipelining, read every response, so that nothing piles up in a
// socket that is written to six hundred times.
type http1Connection struct {
	streams *http.Transport
	packets *http.Transport
	tracker connTracker
}

func newHTTP1Connection(dialer N.Dialer, tlsDialer tls.Dialer, serverAddr M.Socksaddr) *http1Connection {
	connection := &http1Connection{}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if tlsDialer != nil {
			return connection.tracker.track(tlsDialer.DialTLSContext(ctx, serverAddr))
		}
		return connection.tracker.track(dialer.DialContext(ctx, N.NetworkTCP, serverAddr))
	}
	connection.streams = &http.Transport{
		DialContext:       dial,
		DialTLSContext:    dial,
		DisableKeepAlives: true,
		IdleConnTimeout:   connectionIdleTimeout,
	}
	connection.packets = &http.Transport{
		DialContext:         dial,
		DialTLSContext:      dial,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     connectionIdleTimeout,
	}
	return connection
}

func (c *http1Connection) roundTrip(request *http.Request) (*http.Response, error) {
	if isPacketRequest(request) {
		return c.packets.RoundTrip(request)
	}
	return c.streams.RoundTrip(request)
}

func (c *http1Connection) close() {
	c.streams.CloseIdleConnections()
	c.packets.CloseIdleConnections()
	c.tracker.closeAll()
}

type packetRequestKey struct{}

// isPacketRequest tells a packet-up upload (which may be a GET with its data in
// headers) from a download.
func isPacketRequest(request *http.Request) bool {
	return request.Context().Value(packetRequestKey{}) != nil
}

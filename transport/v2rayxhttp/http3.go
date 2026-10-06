//go:build with_quic

package v2rayxhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	congestion_meta1 "github.com/sagernet/sing-quic/congestion_meta1"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// quicKeepAlivePeriod is the QUIC keep-alive of an idle HTTP/3 connection
// (Xray's net.QuicgoH3KeepAlivePeriod).
const quicKeepAlivePeriod = 10 * time.Second

// maxLaneRequests is how many requests at a time one QUIC connection is given.
// A server allows so many open streams to a connection, 100 with quic-go's
// defaults (Xray) and with the common servers and CDNs, and the HTTP/3 client
// waits for a free one where the HTTP/2 client opens another connection: the
// sessions past the limit hung until others ended (lab: 250 sessions held, 300
// not). The margin is for the streams the server has not counted closed yet.
const maxLaneRequests = 90

// laneIdleTimeout closes a QUIC connection added for a burst once it has had
// no request for this long.
const laneIdleTimeout = 30 * time.Second

// http3Connection carries the requests of its sessions as streams of a QUIC
// connection, and of more connections (lanes) while one is full.
type http3Connection struct {
	newTransport func(lane *http3Lane) *http3.Transport

	access sync.Mutex
	lanes  []*http3Lane
	closed bool
}

// http3Lane is one QUIC connection of an http3Connection.
type http3Lane struct {
	owner     *http3Connection
	transport *http3.Transport
	// requests on their way, and the timer that closes the lane when there
	// are none; both under the lock of the owner.
	requests  int
	idleTimer *time.Timer
	// conns are the QUIC connections dialed: http3.Transport forgets one whose
	// request failed without closing it, and its keep-alive then holds it,
	// its socket and its goroutines open.
	conns  map[*quic.Conn]struct{}
	closed bool
	// ctx is done when the lane closes: a dial does not outlive it.
	ctx    context.Context
	cancel context.CancelFunc
}

func (l *http3Lane) track(conn *quic.Conn) bool {
	c := l.owner
	c.access.Lock()
	defer c.access.Unlock()
	if l.closed {
		return false
	}
	if l.conns == nil {
		l.conns = make(map[*quic.Conn]struct{})
	}
	l.conns[conn] = struct{}{}
	context.AfterFunc(conn.Context(), func() {
		c.access.Lock()
		delete(l.conns, conn)
		c.access.Unlock()
	})
	return true
}

// close closes the lane; the caller has taken it out of the list and marked
// it closed under the lock.
func (l *http3Lane) close(conns map[*quic.Conn]struct{}) {
	l.cancel()
	l.transport.Close()
	for conn := range conns {
		conn.CloseWithError(0, "")
	}
}

// acquire counts a request on a lane with room for it, the first one, so that
// the later ones empty and close; a new lane when all are full.
func (c *http3Connection) acquire() (*http3Lane, error) {
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	var lane *http3Lane
	for _, candidate := range c.lanes {
		if candidate.requests < maxLaneRequests {
			lane = candidate
			break
		}
	}
	if lane == nil {
		lane = &http3Lane{owner: c}
		lane.ctx, lane.cancel = context.WithCancel(context.Background())
		lane.transport = c.newTransport(lane)
		c.lanes = append(c.lanes, lane)
	}
	lane.requests++
	if lane.idleTimer != nil {
		lane.idleTimer.Stop()
		lane.idleTimer = nil
	}
	return lane, nil
}

func (c *http3Connection) release(lane *http3Lane) {
	c.access.Lock()
	defer c.access.Unlock()
	lane.requests--
	// the first lane stays: the pool retires the whole connection when idle
	if lane.requests > 0 || lane.closed || len(c.lanes) == 0 || c.lanes[0] == lane {
		return
	}
	lane.idleTimer = time.AfterFunc(laneIdleTimeout, func() {
		c.access.Lock()
		if lane.requests > 0 || lane.closed {
			c.access.Unlock()
			return
		}
		lane.closed = true
		for i, other := range c.lanes {
			if other == lane {
				c.lanes = append(c.lanes[:i], c.lanes[i+1:]...)
				break
			}
		}
		conns := lane.conns
		lane.conns = nil
		c.access.Unlock()
		lane.close(conns)
	})
}

// laneBody ends the count of its request when the response body is closed.
type laneBody struct {
	io.ReadCloser
	release func()
}

func (b *laneBody) Close() error {
	err := b.ReadCloser.Close()
	b.release()
	return err
}

func newHTTP3Connections(dialer N.Dialer, serverAddr M.Socksaddr, tlsConfig tls.Config, keepAlivePeriod time.Duration) (func() pooledConnection, error) {
	stdConfig, err := tls.STDConfigForQUIC(tlsConfig)
	if err != nil {
		return nil, E.Cause(err, "xhttp: HTTP/3 TLS")
	}
	stdConfig = stdConfig.Clone()
	stdConfig.NextProtos = []string{http3.NextProtoH3}
	switch {
	case keepAlivePeriod == 0:
		keepAlivePeriod = quicKeepAlivePeriod
	case keepAlivePeriod < 0:
		keepAlivePeriod = 0
	}
	quicConfig := &quic.Config{
		MaxIdleTimeout:          connectionIdleTimeout,
		KeepAlivePeriod:         keepAlivePeriod,
		MaxIncomingStreams:      -1,
		DisablePathMTUDiscovery: !(runtime.GOOS == "linux" || runtime.GOOS == "windows" || runtime.GOOS == "darwin"),
	}
	return func() pooledConnection {
		connection := &http3Connection{}
		connection.newTransport = func(lane *http3Lane) *http3.Transport {
			return &http3.Transport{
				TLSClientConfig: stdConfig,
				QUICConfig:      quicConfig,
				Dial: func(ctx context.Context, addr string, tlsConfig *tls.STDConfig, quicConfig *quic.Config) (*quic.Conn, error) {
					// The connection is shared: the session whose request started
					// the dial must not take it down, by closing, for the sessions
					// waiting for it.
					// It ends with its lane: closing the HTTP/3 client waits for
					// a dial in progress.
					ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), C.TCPTimeout)
					defer cancel()
					defer context.AfterFunc(lane.ctx, cancel)()
					// http3.Transport fills an empty server name from the request's
					// host, which would undo disable_sni.
					tlsConfig = tlsConfig.Clone()
					tlsConfig.ServerName = stdConfig.ServerName
					conn, err := dialer.DialContext(ctx, N.NetworkUDP, serverAddr)
					if err != nil {
						return nil, err
					}
					quicConn, err := quic.DialEarly(ctx, bufio.NewUnbindPacketConn(conn), conn.RemoteAddr(), tlsConfig, quicConfig)
					if err != nil {
						conn.Close()
						return nil, err
					}
					// quic-go does not own a packet conn passed to DialEarly: it
					// only stops reading it when the connection ends.
					context.AfterFunc(quicConn.Context(), func() {
						conn.Close()
					})
					// BBR, as Xray's HTTP/3 uses.
					quicConn.SetCongestionControl(congestion_meta2.NewBbrSender(
						congestion_meta2.DefaultClock{TimeFunc: time.Now},
						congestion.ByteCount(quicConn.Config().InitialPacketSize),
						congestion.ByteCount(congestion_meta1.InitialCongestionWindow),
					))
					if !lane.track(quicConn) {
						quicConn.CloseWithError(0, "")
						return nil, net.ErrClosed
					}
					return quicConn, nil
				},
			}
		}
		return connection
	}, nil
}

func (c *http3Connection) roundTrip(request *http.Request) (*http.Response, error) {
	lane, err := c.acquire()
	if err != nil {
		return nil, err
	}
	var once sync.Once
	release := func() { once.Do(func() { c.release(lane) }) }
	response, err := lane.transport.RoundTrip(request)
	if err != nil {
		release()
		return nil, err
	}
	response.Body = &laneBody{response.Body, release}
	// a request given up by its context frees its stream as well
	context.AfterFunc(request.Context(), release)
	return response, nil
}

func (c *http3Connection) close() {
	c.access.Lock()
	lanes := c.lanes
	c.lanes = nil
	c.closed = true
	conns := make([]map[*quic.Conn]struct{}, len(lanes))
	for i, lane := range lanes {
		lane.closed = true
		if lane.idleTimer != nil {
			lane.idleTimer.Stop()
		}
		conns[i] = lane.conns
		lane.conns = nil
	}
	c.access.Unlock()
	for i, lane := range lanes {
		lane.close(conns[i])
	}
}

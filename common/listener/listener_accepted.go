package listener

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
)

// The TCP connections a listener accepted and its inbound still holds (podkop-engine): those whose
// handler has not returned. The handler of an inbound returns when the connection is closed or when
// the router has it, which closes it with what it dialed; until then nothing but its peer ends it: a
// handshake that does not come, a client of an HTTP proxy between two requests of a connection kept
// alive. When the listener closes, such a connection would be served on by an inbound that is
// closed: the next request of the kept-alive connection would be authenticated by the users the
// inbound had, and answered "502 Bad Gateway" by a router that is closed. They are closed with the
// listener, as an HTTP server closes its idle connections; a client dials again.
type acceptedConns struct {
	access sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

// add takes a connection, false once the listener is closed.
func (c *acceptedConns) add(conn net.Conn) bool {
	c.access.Lock()
	defer c.access.Unlock()
	if c.closed {
		return false
	}
	if c.conns == nil {
		c.conns = make(map[net.Conn]struct{})
	}
	c.conns[conn] = struct{}{}
	return true
}

func (c *acceptedConns) remove(conn net.Conn) {
	c.access.Lock()
	defer c.access.Unlock()
	delete(c.conns, conn)
}

// close closes the connections held, and those accepted from now on.
func (c *acceptedConns) close() {
	c.access.Lock()
	conns := c.conns
	c.conns, c.closed = nil, true
	c.access.Unlock()
	for conn := range conns {
		conn.Close()
	}
}

// handleTCP hands a connection to the inbound, which holds it until the call returns.
func (l *Listener) handleTCP(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) {
	if !l.accepted.add(conn) {
		conn.Close()
		return
	}
	defer l.accepted.remove(conn)
	l.connHandler.NewConnection(ctx, conn, metadata, nil)
}

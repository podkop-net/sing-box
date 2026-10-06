package adapter

import (
	"context"
	"net"

	N "github.com/sagernet/sing/common/network"
)

type V2RayServerTransport interface {
	Network() []string
	Serve(listener net.Listener) error
	ServePacket(listener net.PacketConn) error
	Close() error
}

type V2RayServerTransportHandler interface {
	N.TCPConnectionHandlerEx
}

// V2RayClientTransport is the client side of a V2Ray transport, owned by an
// outbound.
//
// Close is a reset, not an end: it closes the connections the transport keeps
// and leaves the transport usable. The outbounds call it from InterfaceUpdated
// on every change of the network, before the first dial as well and any number
// of times, and once more when they close. DialContext after a Close must open
// a new connection and must not fail for the Close.
type V2RayClientTransport interface {
	DialContext(ctx context.Context) (net.Conn, error)
	Close() error
}

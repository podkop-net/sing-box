package route

import (
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/udpnat2"
)

// dnsNatHandoff is how long, after the handler of a session is set, a packet that udpnat
// was queuing meanwhile is waited for.
var dnsNatHandoff = 20 * time.Millisecond

// setDNSNatHandler hands a UDP session of an inbound's NAT table to the handler that
// answers its DNS queries; first tells that the route has read no packet of the session.
//
// udpnat gives a packet to the handler of its session, and queues it while the session
// has none; SetHandler takes what is queued at that moment. A packet that udpnat queues
// after that stays in the queue, and its query gets no answer.
//
// It happens to the packet that opened the session, when no sniff action has read it on
// the way to hijack-dns: udpnat starts the route for a new session before it queues that
// packet. So that packet is read from the session before the handler is set, and then
// what reaches the queue shortly after: a packet that came right behind it, which udpnat
// has found without a handler and not queued yet.
//
// After a sniff action the session is handed over as sing-box does it: the sniff has
// read the opening packet, and a wait for a second one would cost every query a timer
// and a wake-up of its own (some 20 us of CPU where it was measured), while a resolver
// such as dnsmasq sends each query from a port of its own. A second packet that comes
// from the same port while the handler is being set can stay in the queue there.
func setDNSNatHandler(conn udpnat.Conn, handler N.UDPHandlerEx, first bool) {
	if !first {
		conn.SetHandler(handler)
		return
	}
	buffer, destination := readDNSNatPacket(conn, C.DNSTimeout)
	// The handler is set before it gets the packet, as SetHandler does with what it takes
	// from the queue: udpnat reads the handler of a session without a lock when it closes
	// the session, and what is started here after SetHandler (the exchange) is what
	// orders that read after it.
	conn.SetHandler(handler)
	for buffer != nil {
		handler.NewPacketEx(buffer, destination)
		buffer, destination = readDNSNatPacket(conn, dnsNatHandoff)
	}
}

// readDNSNatPacket takes a packet from the queue of a session, waiting for one no longer
// than wait; nil when none came or the session is closed.
func readDNSNatPacket(conn udpnat.Conn, wait time.Duration) (*buf.Buffer, M.Socksaddr) {
	buffer := buf.NewPacket()
	conn.SetReadDeadline(time.Now().Add(wait))
	destination, err := conn.ReadPacket(buffer)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		buffer.Release()
		return nil, M.Socksaddr{}
	}
	return buffer, destination
}

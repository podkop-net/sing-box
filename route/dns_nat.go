package route

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/udpnat2"

	mDNS "github.com/miekg/dns"
)

// DNS hijacked from a UDP session of an inbound's NAT table (direct, mixed, socks) is
// answered from a packet handler of the session, as sing-box 1.13 did, not from a
// reading loop per session. dnsmasq forwards every query from a new port, so every query
// is a new session, and the loop kept three goroutines, a timer and buffers alive for
// 10 s after each answer.
func (r *Router) hijackDNSNatConn(ctx context.Context, conn udpnat.Conn, packetBuffers []*N.PacketBuffer, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Destination = M.Socksaddr{}
	handler := &dnsNatHandler{router: r, ctx: ctx, conn: conn, metadata: metadata, onClose: onClose}
	for _, packet := range packetBuffers {
		handler.NewPacketEx(packet.Buffer, packet.Destination)
		N.PutPacketBuffer(packet)
	}
	// the session leaves the table 10 s after its last packet, not after the UDP timeout
	conn.SetTimeout(C.DNSTimeout)
	setDNSNatHandler(conn, handler, len(packetBuffers) == 0)
}

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

type dnsNatHandler struct {
	router   *Router
	ctx      context.Context
	conn     udpnat.Conn
	metadata adapter.InboundContext
	onClose  N.CloseHandlerFunc
}

func (h *dnsNatHandler) NewPacketEx(buffer *buf.Buffer, destination M.Socksaddr) {
	var message mDNS.Msg
	err := message.Unpack(buffer.Bytes())
	buffer.Release()
	if err != nil {
		h.router.logger.ErrorContext(h.ctx, E.Cause(err, "process DNS packet: unpack request"))
		return
	}
	metadata := h.metadata
	// Not on the caller: udpnat calls NewPacketEx from the reading loop of the inbound,
	// which serves every session, and an exchange can wait (a new FakeIP address is
	// written to the cache file, a DoT connection is being set up). The goroutine lives as
	// long as ExchangeAsync itself, not for the session.
	go h.router.dns.ExchangeAsync(adapter.WithContext(h.ctx, &metadata), &message, adapter.DNSQueryOptions{}, func(response *mDNS.Msg, exchangeErr error) {
		if exchangeErr == nil {
			exchangeErr = h.router.writeDNSPacketResponse(&message, response, h.conn, destination)
		}
		if exchangeErr != nil && !R.IsRejected(exchangeErr) && !E.IsClosedOrCanceled(exchangeErr) && !dns.IsLoggedFailure(exchangeErr) {
			h.router.logger.ErrorContext(h.ctx, E.Cause(exchangeErr, "process DNS packet"))
		}
	})
}

// Close is called when the session leaves the NAT table.
func (h *dnsNatHandler) Close() error {
	if h.onClose != nil {
		h.onClose(nil)
	}
	return nil
}

package adapter

import "time"

// QUICStatsOutbound is an outbound whose connections are streams of one QUIC connection of its
// own (Hysteria2, TUIC) (podkop-engine): no connection made through it is a connection of its
// own to the server, so what a connection sees of the path, the outbound tells of its QUIC
// connection instead.
type QUICStatsOutbound interface {
	Outbound
	// QUICStats returns the counts of the current QUIC connection; false when there is none.
	QUICStats() (QUICStats, bool)
}

// QUICStats are the counts of a QUIC connection.
type QUICStats struct {
	// Connection tells one connection from the ones before and after it: counts of two
	// connections cannot be compared.
	Connection uint64
	// PeerPacketsReceived and PeerPacketsMissing are the server's 1-RTT packets that came, each
	// once, and the packet numbers between the smallest and the largest that came that did not
	// (lost on the way, still to come out of order, or skipped by the server).
	PeerPacketsReceived uint64
	PeerPacketsMissing  uint64
	SmoothedRTT         time.Duration
	MinRTT              time.Duration
}

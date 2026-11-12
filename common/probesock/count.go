// Package probesock counts what a probe connection lost on its way to this host
// (podkop-engine).
//
// A loss probe downloads through a server over a TCP connection of its own, opened with a
// small receive buffer: the window the host offers stays at a few segments, so the server
// never sends a burst that a shallow queue on the way (the subscriber's line, mostly) would
// drop. Loss the probe made itself would show on every server alike. While the probe runs,
// the headers of the packets of its connection are captured, and the incoming sequence is
// followed: a hole a later packet fills is reordering when it is filled sooner than a
// quarter of the RTT, and a loss when filled later, by the retransmission of the lost
// segment. The kernel's own counters cannot tell the two apart: its count of out-of-order
// packets grows with the window, not with the loss, and calls a server that reorders lossy.
package probesock

import (
	"time"
)

// Counts are what the capture saw of the incoming data of the probe connection.
type Counts struct {
	Packets      int   // incoming packets with data
	Bytes        int64 // the sequence space they covered, once
	Holes        int   // gaps in the sequence that opened
	LostBytes    int64 // bytes of holes filled late: retransmitted
	LostFills    int   // packets that filled a hole late
	ReorderBytes int64 // bytes of holes filled soon: reordered
	DupBytes     int64 // bytes that came twice
	Unfilled     int64 // bytes of holes still open at the end
	// Broken: the sequence was no stream of a probe (more holes open at once than maxHoles, or
	// more fills than maxFills); the counter stopped there and the counts say nothing
	Broken bool
}

// minReorderWindow is the least time a hole may take to fill and still be reordering: a
// quarter of the RTT, but not less than this, so that the scheduling of the capture on a
// nearby server does not turn reordering into loss.
const minReorderWindow = 3 * time.Millisecond

// reorderWindow is that time for a connection whose connect took rtt.
func reorderWindow(rtt time.Duration) time.Duration {
	return max(rtt/4, minReorderWindow)
}

type hole struct {
	start, end int64
	at         time.Time
}

// fill is a piece of a hole a packet filled: how long the hole had been open, and its bytes.
// The pieces are told apart (reordering or loss) only at the end, by the least RTT of the
// connection: the time of its connect, which a busy host or server stretches, would call
// retransmissions reordering.
type fill struct {
	packet int
	age    time.Duration
	bytes  int64
}

// counter follows the incoming sequence of one connection, packet by packet. Its holes are in the
// order of the sequence and apart from each other: a hole opens past the highest byte, and a
// packet only takes from the holes there are.
type counter struct {
	started bool
	base    uint32
	highest int64
	holes   []hole
	fills   []fill
	Counts
}

// The most a counter keeps. The capture takes every packet with the addresses of the connection,
// whatever its sequence number: what the far end sends is not held to the window (the kernel drops
// what is outside it, after the capture has seen it), and a far end that sends holes without end
// must cost neither memory nor time.
const (
	// maxHoles is the most holes open at once. A sender that keeps to the window the probe offers
	// has all its data that is not acknowledged within Window bytes after the first hole, and a
	// hole takes a missing segment and one that came after it: seven holes with segments of 1448
	// bytes, 19 with segments of 536 (the least MSS of IPv4, RFC 879). 256 holes are open only
	// with segments of 40 bytes, which no download comes in.
	maxHoles = Window / (2 * 40)
	// maxFills is the most pieces of holes filled, in all: one for a segment that came late or
	// out of order. The megabyte of the largest probe (urltest.LossProbeLarge) is 1957 segments
	// of 536 bytes; were every one of them a fill, the count is still under this.
	maxFills = 4096
)

// maxAhead bounds how far past the highest byte a packet may start: a sequence number
// further away is not of this stream (an older packet, wrapped around).
const maxAhead = 1 << 30

// add takes an incoming packet with payload bytes of data starting at seq, captured at at.
func (c *counter) add(at time.Time, seq uint32, payload int) {
	if payload <= 0 || c.Broken {
		return
	}
	if !c.started {
		c.base, c.started = seq, true
	}
	start := int64(seq - c.base)
	if start > c.highest+maxAhead {
		return
	}
	end := start + int64(payload)
	c.Packets++
	if start > c.highest {
		if len(c.holes) >= maxHoles {
			c.broken()
			return
		}
		c.holes = append(c.holes, hole{c.highest, start, at})
		c.Holes++
		c.highest = end
		return
	}
	limit := min(end, c.highest)
	covered := int64(0)
	// the holes are filtered in place: a packet leaves at most one piece of each hole it reaches,
	// but for one that lies inside a single hole and splits it in two (it reaches no other hole)
	kept := 0
	for index := 0; index < len(c.holes); index++ {
		h := c.holes[index]
		from, to := max(start, h.start), min(limit, h.end)
		if from >= to {
			c.holes[kept] = h
			kept++
			continue
		}
		if len(c.fills) >= maxFills {
			c.broken()
			return
		}
		covered += to - from
		c.fills = append(c.fills, fill{packet: c.Packets, age: at.Sub(h.at), bytes: to - from})
		switch {
		case h.start < from && to < h.end:
			// inside the hole: every hole before it was kept as it is (kept == index), and the
			// holes after it move up by one
			if len(c.holes) >= maxHoles {
				c.broken()
				return
			}
			c.holes = append(c.holes, hole{})
			copy(c.holes[index+2:], c.holes[index+1:])
			c.holes[index] = hole{h.start, from, h.at}
			c.holes[index+1] = hole{to, h.end, h.at}
			kept = len(c.holes)
			index = len(c.holes)
		case h.start < from:
			c.holes[kept] = hole{h.start, from, h.at}
			kept++
		case to < h.end:
			c.holes[kept] = hole{to, h.end, h.at}
			kept++
		}
	}
	c.holes = c.holes[:kept]
	c.DupBytes += (limit - start) - covered
	if end > c.highest {
		c.highest = end
	}
}

// broken ends the counting: the sequence is no stream of a probe (maxHoles, maxFills). What was
// kept is let go, and every later packet is passed over.
func (c *counter) broken() {
	c.Broken = true
	c.holes, c.fills = nil, nil
}

// finish returns the counts of the connection so far, the holes filled within window
// counted as reordering, the others as loss. Of a broken counter, only Broken and Packets tell
// anything.
func (c *counter) finish(window time.Duration) Counts {
	counts := c.Counts
	counts.Bytes = c.highest
	for _, h := range c.holes {
		counts.Unfilled += h.end - h.start
	}
	lastLate := -1
	for _, piece := range c.fills {
		if piece.age < window {
			counts.ReorderBytes += piece.bytes
			continue
		}
		counts.LostBytes += piece.bytes
		if piece.packet != lastLate {
			counts.LostFills++
			lastLate = piece.packet
		}
	}
	return counts
}

// segments turns the counts into segments of size mss: how many the data took, and how many
// of them were lost (a lost segment is at least one late fill).
func (c Counts) segments(mss int) (segments int, lost int) {
	if mss <= 0 {
		mss = defaultMSS
	}
	segments = int((c.Bytes + int64(mss) - 1) / int64(mss))
	lost = int((c.LostBytes + int64(mss)/2) / int64(mss))
	lost = max(lost, c.LostFills)
	return
}

// defaultMSS is the segment size when the connection does not tell its own: Ethernet, IPv4,
// TCP timestamps.
const defaultMSS = 1448

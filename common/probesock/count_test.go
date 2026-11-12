package probesock

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func at(milliseconds int) time.Time {
	return time.Unix(1000, 0).Add(time.Duration(milliseconds) * time.Millisecond)
}

func newCounter() *counter {
	return &counter{}
}

const testWindow = 10 * time.Millisecond

func TestCounterInOrder(t *testing.T) {
	c := newCounter()
	for i := 0; i < 10; i++ {
		c.add(at(i), uint32(5000+i*1000), 1000)
	}
	counts := c.finish(testWindow)
	require.Equal(t, int64(10000), counts.Bytes)
	require.Zero(t, counts.Holes)
	require.Zero(t, counts.LostBytes)
	require.Equal(t, 10, counts.Packets)
}

// A hole filled later than the window is a loss: the retransmission of the segment.
func TestCounterLoss(t *testing.T) {
	c := newCounter()
	c.add(at(0), 0, 1000)
	c.add(at(1), 1000, 1000)
	c.add(at(2), 3000, 1000)
	c.add(at(3), 4000, 1000)
	c.add(at(100), 2000, 1000)
	counts := c.finish(testWindow)
	require.Equal(t, 1, counts.Holes)
	require.Equal(t, int64(1000), counts.LostBytes)
	require.Equal(t, 1, counts.LostFills)
	require.Zero(t, counts.ReorderBytes)
	require.Zero(t, counts.Unfilled)
	require.Equal(t, int64(5000), counts.Bytes)
}

// A hole filled within the window is reordering, not a loss.
func TestCounterReorder(t *testing.T) {
	c := newCounter()
	c.add(at(0), 0, 1000)
	c.add(at(1), 2000, 1000)
	c.add(at(2), 1000, 1000)
	counts := c.finish(testWindow)
	require.Equal(t, int64(1000), counts.ReorderBytes)
	require.Zero(t, counts.LostBytes)
	require.Zero(t, counts.LostFills)
}

func TestCounterDuplicateAndUnfilled(t *testing.T) {
	c := newCounter()
	c.add(at(0), 0, 1000)
	c.add(at(1), 0, 1000)
	c.add(at(2), 2000, 1000)
	counts := c.finish(testWindow)
	require.Equal(t, int64(1000), counts.DupBytes)
	require.Equal(t, int64(1000), counts.Unfilled)
}

// A hole of two segments filled late by two retransmissions is two lost segments.
func TestCounterPartialFills(t *testing.T) {
	c := newCounter()
	c.add(at(0), 0, 1000)
	c.add(at(1), 3000, 1000)
	c.add(at(50), 1000, 1000)
	c.add(at(60), 2000, 1000)
	counts := c.finish(testWindow)
	require.Equal(t, int64(2000), counts.LostBytes)
	require.Equal(t, 2, counts.LostFills)
	segments, lost := counts.segments(1000)
	require.Equal(t, 4, segments)
	require.Equal(t, 2, lost)
}

// The sequence number wraps around; a number far behind the stream is not taken.
func TestCounterWrap(t *testing.T) {
	c := newCounter()
	c.add(at(0), 0xffffff00, 0x100)
	c.add(at(1), 0, 1000)
	c.add(at(2), 0x7fff0000, 1000)
	counts := c.finish(testWindow)
	require.Equal(t, int64(0x100+1000), counts.Bytes)
	require.Zero(t, counts.Holes)
}

func TestSegments(t *testing.T) {
	segments, lost := Counts{Bytes: 14480, LostBytes: 1448}.segments(1448)
	require.Equal(t, 10, segments)
	require.Equal(t, 1, lost)
	segments, lost = Counts{Bytes: 14480, LostBytes: 100, LostFills: 2}.segments(0)
	require.Equal(t, 10, segments)
	require.Equal(t, 2, lost)
}

func TestReorderWindow(t *testing.T) {
	require.Equal(t, minReorderWindow, reorderWindow(time.Millisecond))
	require.Equal(t, 25*time.Millisecond, reorderWindow(100*time.Millisecond))
}

// The pieces are told apart by the window given at the end: a longer RTT makes a fill
// reordering that a shorter one calls a loss.
func TestCounterWindowAtTheEnd(t *testing.T) {
	c := newCounter()
	c.add(at(0), 0, 1000)
	c.add(at(1), 2000, 1000)
	c.add(at(30), 1000, 1000)
	require.Equal(t, int64(1000), c.finish(20*time.Millisecond).LostBytes)
	require.Equal(t, int64(1000), c.finish(40*time.Millisecond).ReorderBytes)
	require.Zero(t, c.finish(40*time.Millisecond).LostBytes)
}

// A packet in the middle of a hole splits it; the holes after it stay as they were.
func TestCounterSplitKeepsLaterHoles(t *testing.T) {
	c := newCounter()
	c.add(at(0), 0, 1000)
	c.add(at(1), 4000, 1000)
	c.add(at(2), 6000, 1000)
	// holes [1000,4000) and [5000,6000); a retransmission lands in the middle of the first
	c.add(at(50), 2000, 1000)
	c.add(at(60), 1000, 1000)
	c.add(at(70), 3000, 1000)
	c.add(at(80), 5000, 1000)
	counts := c.finish(testWindow)
	require.Equal(t, int64(4000), counts.LostBytes)
	require.Equal(t, 4, counts.LostFills)
	require.Zero(t, counts.DupBytes)
	require.Zero(t, counts.Unfilled)
	require.Equal(t, int64(7000), counts.Bytes)
}

// reference is the counter as it was before its holes were kept in place and bounded: a new list
// of holes for every packet at or below the highest byte, nothing bounded.
type reference struct {
	started bool
	base    uint32
	highest int64
	holes   []hole
	fills   []fill
	Counts
}

func (c *reference) add(at time.Time, seq uint32, payload int) {
	if payload <= 0 {
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
		c.holes = append(c.holes, hole{c.highest, start, at})
		c.Holes++
		c.highest = end
		return
	}
	limit := min(end, c.highest)
	covered := int64(0)
	kept := make([]hole, 0, len(c.holes)+1)
	for _, h := range c.holes {
		from, to := max(start, h.start), min(limit, h.end)
		if from >= to {
			kept = append(kept, h)
			continue
		}
		covered += to - from
		c.fills = append(c.fills, fill{packet: c.Packets, age: at.Sub(h.at), bytes: to - from})
		if h.start < from {
			kept = append(kept, hole{h.start, from, h.at})
		}
		if to < h.end {
			kept = append(kept, hole{to, h.end, h.at})
		}
	}
	c.holes = kept
	c.DupBytes += (limit - start) - covered
	if end > c.highest {
		c.highest = end
	}
}

// The holes kept in place count what the list made anew for every packet counted: streams of
// segments lost and sent again (whole, in parts, with their neighbours), out of order and twice.
func TestCounterAsReference(t *testing.T) {
	for seed := int64(1); seed <= 200; seed++ {
		random := rand.New(rand.NewSource(seed))
		type packet struct {
			seq     uint32
			payload int
			at      int
		}
		var packets []packet
		base := uint32(random.Int63())
		offset, clock := 0, 0
		var late []packet
		for segment := 0; segment < 300; segment++ {
			size := 1 + random.Intn(1448)
			p := packet{base + uint32(offset), size, 0}
			offset += size
			switch choice := random.Intn(20); {
			case choice == 0:
				// lost: sent again later, whole, in two parts, or with bytes of its neighbours
				switch random.Intn(3) {
				case 0:
					late = append(late, p)
				case 1:
					half := 1 + random.Intn(size)
					late = append(late, packet{p.seq, half, 0}, packet{p.seq + uint32(half), size - half, 0})
				default:
					before := min(random.Intn(700), int(p.seq-base))
					late = append(late, packet{p.seq - uint32(before), size + before + random.Intn(700), 0})
				}
			case choice == 1:
				// twice
				packets = append(packets, p, p)
			case choice == 2 && len(packets) > 0:
				// out of order: before the packet that came before it
				last := packets[len(packets)-1]
				packets[len(packets)-1] = p
				packets = append(packets, last)
			default:
				packets = append(packets, p)
			}
			if len(late) > 0 && random.Intn(4) == 0 {
				index := random.Intn(len(late))
				packets = append(packets, late[index])
				late = append(late[:index], late[index+1:]...)
			}
		}
		// some of the lost are never sent again: holes open at the end
		for len(late) > 2 {
			packets = append(packets, late[0])
			late = late[1:]
		}
		counted, expected := newCounter(), &reference{}
		for _, p := range packets {
			clock += random.Intn(12)
			counted.add(at(clock), p.seq, p.payload)
			expected.add(at(clock), p.seq, p.payload)
		}
		require.False(t, counted.Broken, "seed %d", seed)
		require.Equal(t, len(expected.holes), len(counted.holes), "seed %d", seed)
		for index := range expected.holes {
			require.Equal(t, expected.holes[index], counted.holes[index], "seed %d, hole %d", seed, index)
		}
		require.Equal(t, len(expected.fills), len(counted.fills), "seed %d", seed)
		for index := range expected.fills {
			require.Equal(t, expected.fills[index], counted.fills[index], "seed %d, fill %d", seed, index)
		}
		for _, window := range []time.Duration{0, testWindow, time.Second} {
			want := (&counter{highest: expected.highest, holes: expected.holes, fills: expected.fills, Counts: expected.Counts}).finish(window)
			require.Equal(t, want, counted.finish(window), "seed %d", seed)
		}
	}
}

// A far end that opens holes without end (every packet past the highest byte) is no stream of a
// probe: the counter keeps maxHoles of them and stops.
func TestCounterHolesBounded(t *testing.T) {
	c := newCounter()
	c.add(at(0), 0, 1)
	for i := 1; i <= maxHoles; i++ {
		c.add(at(i), uint32(2*i), 1)
	}
	require.False(t, c.Broken)
	require.Len(t, c.holes, maxHoles)
	c.add(at(1000), uint32(2*maxHoles+2), 1)
	require.True(t, c.Broken)
	require.Nil(t, c.holes)
	require.Nil(t, c.fills)
	packets := c.Packets
	for i := 0; i < 100000; i++ {
		c.add(at(2000+i), uint32(3*maxHoles+2*i), 1)
		c.add(at(2000+i), uint32(i), 1)
	}
	require.Equal(t, packets, c.Packets)
	require.Nil(t, c.holes)
	require.True(t, c.finish(testWindow).Broken)
}

// Nor do packets that split the holes there are: a hole of maxHoles*4 bytes cut by a byte at
// every fourth breaks the counter at maxHoles holes.
func TestCounterSplitsBounded(t *testing.T) {
	c := newCounter()
	c.add(at(0), 0, 1)
	c.add(at(1), uint32(8*maxHoles), 1)
	require.Len(t, c.holes, 1)
	for i := 1; i < 2*maxHoles && !c.Broken; i++ {
		c.add(at(1+i), uint32(4*i), 1)
		require.LessOrEqual(t, len(c.holes), maxHoles)
	}
	require.True(t, c.Broken)
}

// A hole filled a byte at a time is fills without end: the counter keeps maxFills and stops.
func TestCounterFillsBounded(t *testing.T) {
	c := newCounter()
	c.add(at(0), 0, 1)
	c.add(at(1), uint32(2*maxFills), 1)
	for i := 1; i <= maxFills; i++ {
		c.add(at(1+i), uint32(i), 1)
	}
	require.False(t, c.Broken)
	require.Len(t, c.fills, maxFills)
	require.Len(t, c.holes, 1)
	c.add(at(100000), uint32(maxFills+1), 1)
	require.True(t, c.Broken)
	require.Nil(t, c.fills)
}

// The largest probe at the least segments, every other one lost and sent again, is within the
// bounds: the bounds leave out no stream of a probe.
func TestCounterBoundsHoldAProbe(t *testing.T) {
	const segment, size = 536, 1 << 20
	const total, perWindow = (size + segment - 1) / segment, Window / segment
	c := newCounter()
	clock, shown := 0, 0
	length := func(index int) int { return min(segment, size-index*segment) }
	// the sender keeps to the window: what it sent and is not acknowledged is within Window
	// bytes after the first hole, so the lost segments of a window are sent again before the next
	for first := 0; first < total; first += perWindow {
		last := min(first+perWindow, total) - 1
		var lost []int
		for index := first; index <= last; index++ {
			if index%2 == 1 {
				lost = append(lost, index)
				if index < last {
					// a segment came after it: a hole
					shown++
				}
				continue
			}
			clock++
			c.add(at(clock), uint32(index*segment), length(index))
		}
		require.LessOrEqual(t, len(c.holes), Window/(2*segment)+1)
		for _, index := range lost {
			clock += 50
			c.add(at(clock), uint32(index*segment), length(index))
		}
		require.False(t, c.Broken)
		require.Empty(t, c.holes)
	}
	counts := c.finish(testWindow)
	require.False(t, counts.Broken)
	require.Zero(t, counts.Unfilled)
	require.Equal(t, int64(size), counts.Bytes)
	require.Equal(t, shown, len(c.fills))
	require.Less(t, len(c.fills), maxFills)
	segments, lostSegments := counts.segments(segment)
	require.Equal(t, total, segments)
	require.Equal(t, shown, lostSegments)
}

// A packet at or below the highest byte allocates nothing while it splits no hole.
func TestCounterAddAllocatesNothing(t *testing.T) {
	c := newCounter()
	c.add(at(0), 0, 1)
	for i := 1; i <= maxHoles; i++ {
		c.add(at(i), uint32(2*i), 1)
	}
	allocations := testing.AllocsPerRun(1000, func() {
		// twice the first byte: every hole is looked at, none is changed
		c.add(at(5000), 0, 1)
	})
	require.Zero(t, allocations)
}

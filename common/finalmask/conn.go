package finalmask

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// fragmentConn cuts the writes of a connection as Xray's fragment mask does
// (fragment/conn.go of Xray-core). Reading is not touched. A pause between pieces ends when
// the connection is closed or its write deadline passes.
type fragmentConn struct {
	net.Conn
	mask *fragment
	// writes begun, and writes done: the mask steps aside only after the last one it cuts
	count     atomic.Int64
	done      atomic.Int64
	deadline  atomic.Int64
	closeOnce sync.Once
	closed    chan struct{}
}

func newFragmentConn(conn net.Conn, mask *fragment) *fragmentConn {
	return &fragmentConn{Conn: conn, mask: mask, closed: make(chan struct{})}
}

func (c *fragmentConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (c *fragmentConn) setDeadline(t time.Time) {
	if t.IsZero() {
		c.deadline.Store(0)
	} else {
		c.deadline.Store(t.UnixNano())
	}
}

func (c *fragmentConn) SetDeadline(t time.Time) error {
	c.setDeadline(t)
	return c.Conn.SetDeadline(t)
}

func (c *fragmentConn) SetWriteDeadline(t time.Time) error {
	c.setDeadline(t)
	return c.Conn.SetWriteDeadline(t)
}

func (c *fragmentConn) pause(delay span) error {
	if delay.to <= 0 {
		return nil
	}
	wait := time.Duration(delay.draw()) * time.Millisecond
	expired := false
	if deadline := c.deadline.Load(); deadline != 0 {
		left := time.Until(time.Unix(0, deadline))
		if left <= 0 {
			return os.ErrDeadlineExceeded
		}
		if left < wait {
			wait, expired = left, true
		}
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		if expired {
			return os.ErrDeadlineExceeded
		}
		return nil
	case <-c.closed:
		return net.ErrClosed
	}
}

// pieceEnd is where a piece that starts at from ends: its drawn length, bounded by the bytes
// left (a length near the largest int does not wrap on 32 bits), and the rest for the last
// piece max_split allows.
func (c *fragmentConn) pieceEnd(from, size int, piece, maxSplit int64) int {
	length := c.mask.lengthOf(piece).draw()
	if length > int64(size-from) || maxSplit > 0 && piece+1 >= maxSplit {
		return size
	}
	return from + int(length)
}

func (c *fragmentConn) Write(p []byte) (int, error) {
	count := c.count.Add(1)
	defer c.done.Add(1)
	mask := c.mask
	if mask.packetsFrom == 0 && mask.packetsTo == 1 {
		return c.writeHello(p, count)
	}
	if mask.packetsFrom != 0 && (count < mask.packetsFrom || count > mask.packetsTo) {
		return c.Conn.Write(p)
	}
	maxSplit := mask.maxSplit.draw()
	var piece int64
	for from := 0; ; {
		to := c.pieceEnd(from, len(p), piece, maxSplit)
		n, err := c.Conn.Write(p[from:to])
		from += n
		if err != nil {
			return from, err
		}
		// as in Xray, the pause follows every piece, the last one too
		err = c.pause(mask.delayOf(piece))
		if err != nil {
			return from, err
		}
		piece++
		if from >= len(p) {
			return from, nil
		}
	}
}

// writeHello cuts the first write, when it is a whole TLS record of a ClientHello, into
// records ("tlshello"). Anything else goes as it is: Xray takes any first record of the
// handshake, which a client's first write that only looks like one (the random salt of
// Shadowsocks, one time in 256) would lose its bytes to; a record of no byte is no hello.
func (c *fragmentConn) writeHello(p []byte, count int64) (int, error) {
	if count != 1 || len(p) <= 5 || p[0] != 22 || p[1] != 3 || p[5] != 1 {
		return c.Conn.Write(p)
	}
	recordLength := 5 + (int(p[3])<<8 | int(p[4]))
	if len(p) < recordLength || recordLength == 5 {
		return c.Conn.Write(p)
	}
	mask := c.mask
	data := p[5:recordLength]
	merged := mask.merged()
	var out []byte
	if merged {
		// each piece of n bytes gets a header of 5
		out = make([]byte, 0, len(data)+5*(len(data)/max(int(mask.lengths[0].from), 1)+2))
	}
	maxSplit := mask.maxSplit.draw()
	var piece int64
	for from := 0; from < len(data); piece++ {
		to := c.pieceEnd(from, len(data), piece, maxSplit)
		length := to - from
		record := append(append([]byte(nil), p[0], p[1], p[2], byte(length>>8), byte(length)), data[from:to]...)
		from = to
		if merged {
			out = append(out, record...)
			continue
		}
		_, err := c.Conn.Write(record)
		if err != nil {
			return 0, err
		}
		err = c.pause(mask.delayOf(piece))
		if err != nil {
			return 0, err
		}
	}
	if len(out) > 0 {
		_, err := c.Conn.Write(out)
		if err != nil {
			return 0, err
		}
	}
	if len(p) > recordLength {
		n, err := c.Conn.Write(p[recordLength:])
		if err != nil {
			return recordLength + n, err
		}
	}
	return len(p), nil
}

// ReaderReplaceable: reads are not touched.
func (c *fragmentConn) ReaderReplaceable() bool {
	return true
}

// WriterReplaceable: the writes past the ones the mask cuts may go to the connection under
// it directly, once the last of those is done. Cutting every write ("" packets), it never
// steps aside.
func (c *fragmentConn) WriterReplaceable() bool {
	done := c.done.Load()
	switch {
	case c.mask.packetsFrom == 0 && c.mask.packetsTo == 1:
		return done >= 1
	case c.mask.packetsFrom == 0:
		return false
	default:
		return done >= c.mask.packetsTo
	}
}

func (c *fragmentConn) Upstream() any {
	return c.Conn
}

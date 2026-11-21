// Package finalmask puts Xray's finalmask masks on the TCP connections of an outbound: what
// goes over the wire is reshaped, what it carries is not. Only "fragment" is here, the one
// mask a server does not see (transport/internet/finalmask/fragment of Xray-core, 26.x): it
// cuts the ClientHello into small TLS records, or the first writes of a connection into
// small pieces, so that a DPI box that reads the handshake in one piece does not find it.
package finalmask

import (
	"math/rand/v2"
	"net"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// Masks are the masks of one outbound, in the order of its options (the first one outermost).
type Masks struct {
	fragments []*fragment
}

// New reads the masks; nil when there are none.
func New(options *option.FinalMaskOptions) (*Masks, error) {
	if options == nil || len(options.TCP) == 0 {
		return nil, nil
	}
	masks := &Masks{}
	for index, mask := range options.TCP {
		switch strings.ToLower(mask.Type) {
		case "fragment":
			built, err := newFragment(mask)
			if err != nil {
				return nil, E.Cause(err, "finalmask.tcp[", index, "]")
			}
			masks.fragments = append(masks.fragments, built)
		default:
			return nil, E.New("finalmask.tcp[", index, "]: the mask ", mask.Type, " is not supported (only fragment)")
		}
	}
	return masks, nil
}

// Client puts the masks on a TCP connection the outbound opened. As in Xray (NewFinalMask
// reverses the list before it wraps the connection), the last mask of the list is the one
// nearest to the socket and the first one takes the writes first: [tlshello, 1-1] cuts the
// ClientHello into records and then the first write, those records, into pieces, while
// [1-1, tlshello] cuts the hello into pieces that tlshello then leaves alone (no piece is a
// whole record).
func (m *Masks) Client(conn net.Conn) net.Conn {
	if m == nil {
		return conn
	}
	for index := len(m.fragments) - 1; index >= 0; index-- {
		conn = newFragmentConn(conn, m.fragments[index])
	}
	return conn
}

// a range of whole numbers, drawn as Xray's crypto.RandBetween draws it: from included, to
// left out, and from alone when they are 1 apart or less ("11-24" gives 11 to 23)
type span struct{ from, to int64 }

func (s span) draw() int64 {
	from, to := s.from, s.to
	if from > to {
		from, to = to, from
	}
	if to-from <= 1 {
		return from
	}
	return from + rand.Int64N(to-from)
}

func spanOf(value *option.V2RayXHTTPRange) span {
	if value == nil {
		return span{}
	}
	return span{int64(value.From), int64(value.To)}
}

// fragment is a fragment mask as Xray builds it (infra/conf FragmentMask.Build).
type fragment struct {
	// the writes cut, counted from 1: 0-1 is the ClientHello ("tlshello"), 0-0 every write
	packetsFrom, packetsTo int64
	lengths, delays        []span
	maxSplit               span
}

func newFragment(options option.FinalMaskTCPOptions) (*fragment, error) {
	f := &fragment{}
	switch packets := strings.ToLower(strings.TrimSpace(options.Packets)); packets {
	case "tlshello":
		f.packetsFrom, f.packetsTo = 0, 1
	case "":
	default:
		var bounds option.V2RayXHTTPRange
		err := bounds.UnmarshalJSON([]byte(`"` + packets + `"`))
		if err != nil {
			return nil, E.Cause(err, "packets")
		}
		if bounds.From <= 0 {
			return nil, E.New("packets: the first write is 1")
		}
		f.packetsFrom, f.packetsTo = int64(bounds.From), int64(bounds.To)
	}
	if len(options.Lengths) > 0 {
		for index := range options.Lengths {
			f.lengths = append(f.lengths, spanOf(&options.Lengths[index]))
		}
	} else {
		f.lengths = append(f.lengths, spanOf(options.Length))
	}
	for _, length := range f.lengths {
		if length.from < 0 {
			return nil, E.New("length: a negative length")
		}
	}
	// a piece of no byte is no piece: Xray refuses a last range that may draw 0
	if f.lengths[len(f.lengths)-1].from <= 0 {
		return nil, E.New("length: the last range must start above 0")
	}
	if len(options.Delays) > 0 {
		for index := range options.Delays {
			f.delays = append(f.delays, spanOf(&options.Delays[index]))
		}
	} else {
		f.delays = append(f.delays, spanOf(options.Delay))
	}
	for _, delay := range f.delays {
		if delay.from < 0 {
			return nil, E.New("delay: a negative delay")
		}
	}
	f.maxSplit = spanOf(options.MaxSplit)
	if f.maxSplit.from < 0 {
		return nil, E.New("max_split: a negative number")
	}
	return f, nil
}

func (f *fragment) lengthOf(piece int64) span {
	return f.lengths[min(piece, int64(len(f.lengths)-1))]
}

func (f *fragment) delayOf(piece int64) span {
	return f.delays[min(piece, int64(len(f.delays)-1))]
}

// merged: with one delay of 0 the records of a ClientHello go out in one write (Xray's
// mergeTlsHelloSegments)
func (f *fragment) merged() bool {
	return len(f.delays) == 1 && f.delays[0].to == 0
}

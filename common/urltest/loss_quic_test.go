package urltest

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/probesock"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// quicCounterStub counts as a QUIC connection would: every window the server sends brings
// packets, some of them missing.
type quicCounterStub struct {
	received, missing atomic.Uint64
	connection        atomic.Uint64
	none              bool
}

func (s *quicCounterStub) QUICStats() (adapter.QUICStats, bool) {
	if s.none {
		return adapter.QUICStats{}, false
	}
	return adapter.QUICStats{Connection: s.connection.Load(), PeerPacketsReceived: s.received.Load(),
		PeerPacketsMissing: s.missing.Load(), MinRTT: 7 * time.Millisecond}, true
}

func plainDialer() DialerFunc {
	return func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, destination.String())
	}
}

// rangeServer serves a body of total bytes by ranges; each window adds 15 packets that came and
// 1 that did not to the counter. ranges returns the sizes of the ranges asked for.
func rangeServer(t *testing.T, total int, counter *quicCounterStub) (server *httptest.Server, ranges func() []int64) {
	body := make([]byte, total)
	var access sync.Mutex
	var asked []int64
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		spec := strings.TrimPrefix(r.Header.Get("Range"), "bytes=")
		if from, to, found := strings.Cut(spec, "-"); found {
			a, _ := strconv.ParseInt(from, 10, 64)
			b, _ := strconv.ParseInt(to, 10, 64)
			access.Lock()
			asked = append(asked, b-a+1)
			access.Unlock()
		}
		counter.received.Add(15)
		counter.missing.Add(1)
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body))
	}))
	t.Cleanup(server.Close)
	return server, func() []int64 {
		access.Lock()
		defer access.Unlock()
		return append([]int64(nil), asked...)
	}
}

// The probe asks for one window at a time and counts what the connection counted across it.
func TestLossProbeQUICWindows(t *testing.T) {
	counter := &quicCounterStub{}
	server, ranges := rangeServer(t, LossProbeSmall, counter)
	sample, err := LossProbeQUIC(context.Background(), server.URL, LossProbeSmall, plainDialer(), counter)
	require.NoError(t, err)
	windows := (LossProbeSmall + probesock.Window - 1) / probesock.Window
	require.Len(t, ranges(), windows)
	for _, size := range ranges() {
		require.LessOrEqual(t, size, int64(probesock.Window))
	}
	require.Equal(t, int64(LossProbeSmall), sample.Received)
	require.Equal(t, 16*windows, sample.Segments)
	require.Equal(t, windows, sample.Lost)
	require.Equal(t, 7*time.Millisecond, sample.RTT)
}

// A body shorter than asked is counted as it is.
func TestLossProbeQUICShortBody(t *testing.T) {
	counter := &quicCounterStub{}
	server, _ := rangeServer(t, 50<<10, counter)
	sample, err := LossProbeQUIC(context.Background(), server.URL, LossProbeSmall, plainDialer(), counter)
	require.NoError(t, err)
	require.Equal(t, int64(50<<10), sample.Received)
	require.Positive(t, sample.Segments)
}

// No connection, or one replaced during the probe: nothing is counted.
func TestLossProbeQUICNotCounted(t *testing.T) {
	none := &quicCounterStub{none: true}
	server, _ := rangeServer(t, LossProbeSmall, none)
	_, err := LossProbeQUIC(context.Background(), server.URL, LossProbeSmall, plainDialer(), none)
	require.ErrorIs(t, err, ErrLossNotCounted)
	replaced := &replacedAfterFirst{&quicCounterStub{}}
	server, _ = rangeServer(t, LossProbeSmall, replaced.quicCounterStub)
	_, err = LossProbeQUIC(context.Background(), server.URL, LossProbeSmall, plainDialer(), replaced)
	require.ErrorIs(t, err, ErrLossNotCounted)
}

// replacedAfterFirst is a counter whose connection changes after its first count.
type replacedAfterFirst struct {
	*quicCounterStub
}

func (r *replacedAfterFirst) QUICStats() (adapter.QUICStats, bool) {
	stats, active := r.quicCounterStub.QUICStats()
	r.connection.Add(1)
	return stats, active
}

// A URL that serves no ranges and has no "bytes" parameter would send the whole body at once:
// not a probe, and never one with that URL.
func TestLossProbeQUICNoRanges(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, LossProbeSmall))
	}))
	t.Cleanup(server.Close)
	_, err := LossProbeQUIC(context.Background(), server.URL, LossProbeSmall, plainDialer(), &quicCounterStub{})
	require.ErrorIs(t, err, ErrLossNotCounted)
	require.ErrorIs(t, err, ErrLossNoWindows)
}

// A URL with a "bytes" parameter, as speed.cloudflare.com/__down, which answers a range with the
// whole body: each window is a body of that many bytes.
func TestLossProbeQUICByParameter(t *testing.T) {
	counter := &quicCounterStub{}
	var access sync.Mutex
	var asked []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		size, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
		access.Lock()
		asked = append(asked, r.URL.Query().Get("bytes")+" "+r.Header.Get("Range"))
		access.Unlock()
		counter.received.Add(15)
		w.Write(make([]byte, size))
	}))
	t.Cleanup(server.Close)
	sample, err := LossProbeQUIC(context.Background(), server.URL+"/__down?bytes=1048576", LossProbeSmall, plainDialer(), counter)
	require.NoError(t, err)
	require.Equal(t, int64(LossProbeSmall), sample.Received)
	access.Lock()
	defer access.Unlock()
	windows := (LossProbeSmall + probesock.Window - 1) / probesock.Window
	require.Len(t, asked, windows)
	require.Equal(t, strconv.Itoa(probesock.Window)+" ", asked[0])
	require.Equal(t, strconv.Itoa(LossProbeSmall-(windows-1)*probesock.Window)+" ", asked[windows-1])
	require.Equal(t, 15*windows, sample.Segments)
	require.Zero(t, sample.Lost)
}

// A connection that carried more than the probe (the member in use, busy) weighs as many packets
// as the probe took, at the share the connection lost.
func TestLossProbeQUICBusyConnection(t *testing.T) {
	counter := &quicCounterStub{}
	body := make([]byte, LossProbeSmall)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// the window, and the traffic of the users of the member meanwhile: 1000 packets, 2 % lost
		counter.received.Add(980)
		counter.missing.Add(20)
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body))
	}))
	t.Cleanup(server.Close)
	sample, err := LossProbeQUIC(context.Background(), server.URL, LossProbeSmall, plainDialer(), counter)
	require.NoError(t, err)
	windows := (LossProbeSmall + probesock.Window - 1) / probesock.Window
	require.Equal(t, int(quicProbePackets(LossProbeSmall, windows)), sample.Segments)
	require.InDelta(t, 2.0, 100*float64(sample.Lost)/float64(sample.Segments), 0.6)
}

// A file whose end is the end of a window answers the window after it with 416: the whole of it
// came, and is counted.
func TestLossProbeQUICRangeEnd(t *testing.T) {
	counter := &quicCounterStub{}
	server, _ := rangeServer(t, 2*probesock.Window, counter)
	sample, err := LossProbeQUIC(context.Background(), server.URL, LossProbeSmall, plainDialer(), counter)
	require.NoError(t, err)
	require.Equal(t, int64(2*probesock.Window), sample.Received)
	require.Positive(t, sample.Segments)
}

// idleClosingMember is a member no group uses (sing-quic with closeIdle): its QUIC connection
// closes with its last stream, and the next stream opens another.
type idleClosingMember struct {
	counter quicCounterStub
	access  sync.Mutex
	streams int
	open    bool
}

func (m *idleClosingMember) QUICStats() (adapter.QUICStats, bool) {
	m.access.Lock()
	defer m.access.Unlock()
	if !m.open {
		return adapter.QUICStats{}, false
	}
	return m.counter.QUICStats()
}

func (m *idleClosingMember) dial(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := plainDialer()(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	m.access.Lock()
	if !m.open {
		m.open = true
		m.counter.connection.Add(1)
	}
	m.streams++
	m.access.Unlock()
	return &idleClosingStream{Conn: conn, member: m}, nil
}

type idleClosingStream struct {
	net.Conn
	member *idleClosingMember
	once   sync.Once
}

func (c *idleClosingStream) Close() error {
	c.once.Do(func() {
		c.member.access.Lock()
		c.member.streams--
		if c.member.streams == 0 {
			c.member.open = false
		}
		c.member.access.Unlock()
	})
	return c.Conn.Close()
}

// A window cut by the time limit closes the HTTP connection of the probe: the connection of a member
// no group uses stays until it was counted (the stream the probe holds), and the probe counts as
// far as it came.
func TestLossProbeQUICCutCounts(t *testing.T) {
	member := &idleClosingMember{}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		member.counter.received.Add(15)
		member.counter.missing.Add(1)
		w.Header().Set("Content-Range", "bytes 0-"+strconv.Itoa(probesock.Window-1)+"/"+strconv.Itoa(LossProbeSmall))
		w.Header().Set("Content-Length", strconv.Itoa(probesock.Window))
		w.WriteHeader(http.StatusPartialContent)
		if requests.Add(1) < 3 {
			w.Write(make([]byte, probesock.Window))
			return
		}
		// the third window comes in part, and the rest too late
		w.Write(make([]byte, probesock.Window/2))
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sample, err := LossProbeQUIC(ctx, server.URL, LossProbeSmall, DialerFunc(member.dial), member)
	require.NoError(t, err)
	require.Equal(t, int64(2*probesock.Window+probesock.Window/2), sample.Received)
	require.Equal(t, 3*16, sample.Segments)
	require.Equal(t, 3, sample.Lost)
	// the HTTP connection the cut closed goes in the background of net/http
	require.Eventually(t, func() bool {
		member.access.Lock()
		defer member.access.Unlock()
		return member.streams == 0 && !member.open
	}, 2*time.Second, 10*time.Millisecond, "the connection of a member no group uses is closed after the probe, as before it")
}

func TestParseUDPReceiveDrops(t *testing.T) {
	snmp := "Ip: Forwarding DefaultTTL\nIp: 1 64\n" +
		"Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n" +
		"Udp: 154054 7 3 80910 2 0 0 17450 0\n" +
		"UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n" +
		"UdpLite: 0 0 0 0 9 0 0 0 0\n"
	drops, known := parseUDPReceiveDrops(snmp)
	require.True(t, known)
	require.Equal(t, uint64(2), drops)
	_, known = parseUDPReceiveDrops("Ip: Forwarding\nIp: 1\n")
	require.False(t, known)
}

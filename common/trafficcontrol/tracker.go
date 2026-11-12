package trafficcontrol

import (
	"context"
	"net"
	"slices"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"

	"github.com/gofrs/uuid/v5"
)

type TrackerMetadata struct {
	ID           uuid.UUID
	Metadata     adapter.InboundContext
	CreatedAt    time.Time
	ClosedAt     time.Time
	Upload       *atomic.Int64
	Download     *atomic.Int64
	Chain        []string
	Rule         adapter.Rule
	Outbound     string
	OutboundType string
	// nil but for the TCP connections (podkop-engine)
	stamp *detectStamp
}

// PendingSince returns since when the client of the connection has been waiting for the server
// (detectStamp); zero when it is not, and always for what is not a TCP connection (podkop-engine).
func (m *TrackerMetadata) PendingSince() time.Time {
	if m.stamp == nil {
		return time.Time{}
	}
	since := m.stamp.pendingSince.Load()
	if since == 0 {
		return time.Time{}
	}
	return time.Now().Add(time.Duration(since - detectClock()))
}

// detectStamp tells a client that waits for the server (podkop-engine). A connection cut on the way
// and a healthy one closed by its client look the same at the close, so what the block detector
// reads as a cut is a connection whose client wrote after detectPendingGap with nothing from the
// server, and that got nothing since. A close_notify written at the close does not make one: it has
// to stand for detectCutWait before the close. A client that never writes after the cut is missed.
//
// The times are offsets from detectEpoch, so the first step of the clock of a router with no RTC
// does not make a gap. The download side writes one atomic and reads the clock on every write; the
// upload side reads two atomics, and the clock only while it is not waiting yet.
type detectStamp struct {
	lastDownAt   atomic.Int64
	pendingSince atomic.Int64
}

var detectEpoch = time.Now()

func detectClock() int64 {
	return int64(time.Since(detectEpoch))
}

func (s *detectStamp) downloaded() {
	s.lastDownAt.Store(detectClock())
	if s.pendingSince.Load() != 0 {
		s.pendingSince.Store(0)
	}
}

func (s *detectStamp) uploaded(download int64) {
	if download == 0 || s.pendingSince.Load() != 0 {
		return
	}
	now := detectClock()
	if now-s.lastDownAt.Load() >= int64(detectPendingGap) {
		s.pendingSince.CompareAndSwap(0, now)
	}
}

// waitedAt reports whether a connection closed at closedAt was waiting by then for detectCutWait,
// and since when: one read of the stamp, on the monotonic clock of closedAt.
func (s *detectStamp) waitedAt(closedAt time.Time) (time.Time, bool) {
	since := s.pendingSince.Load()
	if since == 0 {
		return time.Time{}, false
	}
	waited := closedAt.Sub(detectEpoch) - time.Duration(since)
	if waited < detectCutWait {
		return time.Time{}, false
	}
	return closedAt.Add(-waited), true
}

type Tracker interface {
	Metadata() *TrackerMetadata
	Close() error
}

func (m *Manager) RoutedConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) net.Conn {
	upload := new(atomic.Int64)
	download := new(atomic.Int64)
	stamp := new(detectStamp)
	countUpload := func(n int64) {
		upload.Add(n)
		stamp.uploaded(download.Load())
	}
	countDownload := func(n int64) {
		// the stamp first: who sees the bytes finds their time
		stamp.downloaded()
		download.Add(n)
	}
	tracker := &connTracker{
		ExtendedConn: bufio.NewCounterConn(conn, []N.CountFunc{countUpload}, []N.CountFunc{countDownload}),
		metadata:     m.newTrackerMetadata(metadata, matchedRule, matchOutbound, upload, download),
		manager:      m,
	}
	tracker.metadata.stamp = stamp
	m.join(tracker)
	return tracker
}

func (m *Manager) RoutedPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) N.PacketConn {
	upload := new(atomic.Int64)
	download := new(atomic.Int64)
	tracker := &packetConnTracker{
		PacketConn: bufio.NewInt64CounterPacketConn(conn, []*atomic.Int64{upload}, nil, []*atomic.Int64{download}, nil),
		metadata:   m.newTrackerMetadata(metadata, matchedRule, matchOutbound, upload, download),
		manager:    m,
	}
	m.join(tracker)
	return tracker
}

func (m *Manager) RoutedFlow(ctx context.Context, metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound) tun.FlowTracker {
	return &flowTracker{
		metadata: m.newTrackerMetadata(metadata, matchedRule, matchOutbound, new(atomic.Int64), new(atomic.Int64)),
		manager:  m,
	}
}

func (m *Manager) newTrackerMetadata(metadata adapter.InboundContext, matchedRule adapter.Rule, matchOutbound adapter.Outbound, upload *atomic.Int64, download *atomic.Int64) TrackerMetadata {
	id, _ := uuid.NewV4()
	chain := common.Map(metadata.OutboundChain, adapter.Outbound.Tag)
	slices.Reverse(chain)
	outbound := metadata.OutboundChain[len(metadata.OutboundChain)-1]
	trimTrackedMetadata(&metadata)
	return TrackerMetadata{
		ID:           id,
		Metadata:     metadata,
		CreatedAt:    time.Now(),
		Upload:       upload,
		Download:     download,
		Chain:        chain,
		Rule:         matchedRule,
		Outbound:     outbound.Tag(),
		OutboundType: outbound.Type(),
	}
}

// trimTrackedMetadata drops from the tracker's copy what only routing needed: the sniffer's
// working state (for QUIC, the fragments of the client hello collected so far) and the DNS
// answers. A tracker lives as long as its connection, and then in the list of closed
// connections.
func trimTrackedMetadata(metadata *adapter.InboundContext) {
	metadata.SniffContext = nil
	metadata.SniffError = nil
	metadata.DNSResponse = nil
	metadata.NamedDNSResponses = nil
}

var _ adapter.RemoteEOFMarker = (*connTracker)(nil)

type connTracker struct {
	N.ExtendedConn
	metadata  TrackerMetadata
	manager   *Manager
	remoteEOF atomic.Bool
}

func (t *connTracker) MarkRemoteEOF() {
	t.remoteEOF.Store(true)
}

func (t *connTracker) Metadata() *TrackerMetadata {
	return &t.metadata
}

func (t *connTracker) Close() error {
	t.manager.leave(t)
	return t.ExtendedConn.Close()
}

func (t *connTracker) Upstream() any {
	return t.ExtendedConn
}

func (t *connTracker) ReaderReplaceable() bool {
	return true
}

func (t *connTracker) WriterReplaceable() bool {
	return true
}

var (
	_ Tracker         = (*flowTracker)(nil)
	_ tun.FlowTracker = (*flowTracker)(nil)
)

type flowTracker struct {
	metadata TrackerMetadata
	manager  *Manager
	handle   tun.FlowHandle
}

func (t *flowTracker) Metadata() *TrackerMetadata {
	return &t.metadata
}

func (t *flowTracker) AttachFlow(handle tun.FlowHandle) {
	t.handle = handle
	t.manager.join(t)
}

func (t *flowTracker) CountForward(n int) {
	t.metadata.Upload.Add(int64(n))
}

func (t *flowTracker) CountReverse(n int) {
	t.metadata.Download.Add(int64(n))
}

func (t *flowTracker) FlowEstablished() {
}

func (t *flowTracker) CloseFlow(reason tun.FlowCloseReason) {
	t.manager.leave(t)
}

func (t *flowTracker) Close() error {
	handle := t.handle
	if handle != nil {
		handle.CloseFlow()
	} else {
		t.manager.leave(t)
	}
	return nil
}

type packetConnTracker struct {
	N.PacketConn
	metadata TrackerMetadata
	manager  *Manager
}

func (t *packetConnTracker) Metadata() *TrackerMetadata {
	return &t.metadata
}

func (t *packetConnTracker) Close() error {
	t.manager.leave(t)
	return t.PacketConn.Close()
}

func (t *packetConnTracker) Upstream() any {
	return t.PacketConn
}

func (t *packetConnTracker) ReaderReplaceable() bool {
	return true
}

func (t *packetConnTracker) WriterReplaceable() bool {
	return true
}

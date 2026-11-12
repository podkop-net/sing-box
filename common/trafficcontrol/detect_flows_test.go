package trafficcontrol

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

type detectTestOutbound struct {
	adapter.Outbound
	outboundType string
	tag          string
}

func (o *detectTestOutbound) Type() string { return o.outboundType }
func (o *detectTestOutbound) Tag() string  { return o.tag }

// openFlow makes a TCP connection through an outbound with so many bytes.
func openFlow(t *testing.T, manager *Manager, outboundType, tag string, download, upload int64) *connTracker {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	chain := []adapter.Outbound{&detectTestOutbound{outboundType: outboundType, tag: tag}}
	conn := manager.RoutedConnection(context.Background(), client, adapter.InboundContext{OutboundChain: chain}, nil, chain[0])
	tracker := conn.(*connTracker)
	tracker.metadata.Download.Store(download)
	tracker.metadata.Upload.Store(upload)
	return tracker
}

// closeFlow makes a TCP connection through an outbound and closes it with so many bytes, its client
// waiting for the server for long enough to be a cut.
func closeFlow(t *testing.T, manager *Manager, outboundType, tag string, download, upload int64, remoteEOF bool) {
	t.Helper()
	closeFlowWaited(t, manager, outboundType, tag, download, upload, remoteEOF, 2*detectCutWait)
}

// closeFlowWaited is closeFlow of a connection whose client has waited so long; 0: it does not wait.
func closeFlowWaited(t *testing.T, manager *Manager, outboundType, tag string, download, upload int64, remoteEOF bool, waited time.Duration) {
	t.Helper()
	tracker := openFlow(t, manager, outboundType, tag, download, upload)
	if waited > 0 {
		tracker.metadata.stamp.pendingSince.Store(detectClock() - int64(waited))
	}
	if remoteEOF {
		tracker.MarkRemoteEOF()
	}
	require.NoError(t, tracker.Close())
}

// Only what ended inside the band and was not ended by the server may be a cut.
func TestDetectFlowsBand(t *testing.T) {
	manager := NewManager()
	before := time.Now()
	closeFlow(t, manager, C.TypeVLESS, "s", 0, 100, false)
	require.Empty(t, manager.DetectFlows())
	closeFlow(t, manager, C.TypeVLESS, "s", DetectBandLow-1, 100, false)
	sample := manager.DetectFlows()["s"]
	require.Empty(t, sample.Cuts)
	require.True(t, sample.LastBigAt.IsZero())
	require.False(t, sample.LastDataAt.Before(before))

	closeFlow(t, manager, C.TypeVLESS, "s", DetectBandLow, 100, false)
	closeFlow(t, manager, C.TypeVLESS, "s", DetectBandHigh, 200, false)
	sample = manager.DetectFlows()["s"]
	require.Len(t, sample.Cuts, 2)
	require.Equal(t, int64(DetectBandLow), sample.Cuts[0].Download)
	require.Equal(t, int64(DetectBandHigh), sample.Cuts[1].Download)
	require.Equal(t, int64(200), sample.Cuts[1].Upload)
	require.False(t, sample.Cuts[1].CreatedAt.IsZero())
	require.False(t, sample.Cuts[1].ClosedAt.Before(sample.Cuts[1].CreatedAt))
	require.True(t, sample.LastBigAt.IsZero())

	closeFlow(t, manager, C.TypeVLESS, "s", DetectBandHigh+1, 100, false)
	sample = manager.DetectFlows()["s"]
	require.Len(t, sample.Cuts, 2)
	require.False(t, sample.LastBigAt.IsZero())
}

// The server ended it: a short answer, no cut. It counts as data all the same, and a big one as
// big.
func TestDetectFlowsRemoteEOF(t *testing.T) {
	manager := NewManager()
	closeFlow(t, manager, C.TypeVLESS, "s", 16<<10, 100, true)
	sample := manager.DetectFlows()["s"]
	require.Empty(t, sample.Cuts)
	require.False(t, sample.LastDataAt.IsZero())
	require.True(t, sample.LastBigAt.IsZero())
	closeFlow(t, manager, C.TypeVLESS, "s", DetectBandHigh+1, 100, true)
	require.False(t, manager.DetectFlows()["s"].LastBigAt.IsZero())
}

// Proxy outbounds and TCP only.
func TestDetectFlowsTCPThroughProxyOnly(t *testing.T) {
	manager := NewManager()
	closeFlow(t, manager, C.TypeDirect, "direct", 16<<10, 100, false)
	closeFlow(t, manager, C.TypeBlock, "block", 16<<10, 100, false)
	require.Empty(t, manager.DetectFlows())

	chain := []adapter.Outbound{&detectTestOutbound{outboundType: C.TypeVLESS, tag: "s"}}
	packet := manager.RoutedPacketConnection(context.Background(), nil, adapter.InboundContext{OutboundChain: chain}, nil, chain[0])
	tracker := packet.(*packetConnTracker)
	tracker.metadata.Download.Store(16 << 10)
	manager.join(tracker)
	manager.leave(tracker)
	flow := manager.RoutedFlow(context.Background(), adapter.InboundContext{OutboundChain: chain}, nil, chain[0]).(*flowTracker)
	flow.metadata.Download.Store(16 << 10)
	manager.join(flow)
	manager.leave(flow)
	require.Empty(t, manager.DetectFlows())
}

// Small flows do not push a big one out, and the ring keeps the last possible cuts.
func TestDetectFlowsRing(t *testing.T) {
	manager := NewManager()
	closeFlow(t, manager, C.TypeVLESS, "s", DetectBandHigh+1, 100, false)
	big := manager.DetectFlows()["s"].LastBigAt
	for index := range 2 * detectCutsPerOutbound {
		closeFlow(t, manager, C.TypeVLESS, "s", int64(DetectBandLow+index), 100, false)
	}
	for range 100 {
		closeFlow(t, manager, C.TypeVLESS, "s", 100, 100, false)
	}
	sample := manager.DetectFlows()["s"]
	require.True(t, big.Equal(sample.LastBigAt))
	require.Len(t, sample.Cuts, detectCutsPerOutbound)
	require.Equal(t, int64(DetectBandLow+detectCutsPerOutbound), sample.Cuts[0].Download)
	require.Equal(t, int64(DetectBandLow+2*detectCutsPerOutbound-1), sample.Cuts[detectCutsPerOutbound-1].Download)

	// the outbounds are apart, and the sample returned is the reader's own
	closeFlow(t, manager, C.TypeVLESS, "other", DetectBandLow, 100, false)
	samples := manager.DetectFlows()
	require.Len(t, samples["other"].Cuts, 1)
	samples["s"].Cuts[0].Download = 1
	require.NotEqual(t, int64(1), manager.DetectFlows()["s"].Cuts[0].Download)
}

// Clear runs on every GC, and wipes the list of closed connections only.
func TestDetectFlowsSurviveClear(t *testing.T) {
	manager := NewManager()
	closeFlow(t, manager, C.TypeVLESS, "s", DetectBandHigh+1, 100, false)
	closeFlow(t, manager, C.TypeVLESS, "s", DetectBandLow, 100, false)
	manager.Clear()
	require.Empty(t, manager.ClosedConnections())
	sample := manager.DetectFlows()["s"]
	require.Len(t, sample.Cuts, 1)
	require.False(t, sample.LastBigAt.IsZero())
}

// A healthy flow its client closes first has no EOF of the server either: a cut is a flow whose
// client was waiting for the server at the close, for long enough that it is not a close_notify.
func TestDetectFlowsCutNeedsWaitingClient(t *testing.T) {
	manager := NewManager()
	closeFlowWaited(t, manager, C.TypeVLESS, "s", 16<<10, 100, false, 0)
	closeFlowWaited(t, manager, C.TypeVLESS, "s", 16<<10, 100, false, detectCutWait-time.Second)
	sample := manager.DetectFlows()["s"]
	require.Empty(t, sample.Cuts)
	require.False(t, sample.LastDataAt.IsZero())

	closeFlowWaited(t, manager, C.TypeVLESS, "s", 16<<10, 100, false, detectCutWait+time.Second)
	require.Len(t, manager.DetectFlows()["s"].Cuts, 1)

	// the EOF of the server still decides
	closeFlowWaited(t, manager, C.TypeVLESS, "s", 16<<10, 100, true, detectCutWait+time.Second)
	require.Len(t, manager.DetectFlows()["s"].Cuts, 1)
}

// A cut tells since when its client waited, to the nanosecond of the stamp and on the monotonic
// clock: the reader compares it with when other flows were opened, whatever the wall clock did, to
// tell a cut from an outage.
func TestDetectFlowPendingSince(t *testing.T) {
	manager := NewManager()
	tracker := openFlow(t, manager, C.TypeVLESS, "s", 16<<10, 100)
	stamp := detectClock() - int64(2*detectCutWait)
	tracker.metadata.stamp.pendingSince.Store(stamp)
	require.NoError(t, tracker.Close())

	sample := manager.DetectFlows()["s"]
	require.Len(t, sample.Cuts, 1)
	cut := sample.Cuts[0]
	require.Equal(t, time.Duration(stamp), cut.PendingSince.Sub(detectEpoch))
	require.GreaterOrEqual(t, cut.ClosedAt.Sub(cut.PendingSince), 2*detectCutWait)
	require.Less(t, cut.ClosedAt.Sub(cut.PendingSince), 2*detectCutWait+10*time.Second)
	require.Contains(t, cut.PendingSince.String(), " m=", "a monotonic reading, as CreatedAt has")
	require.Contains(t, cut.CreatedAt.String(), " m=")

	// the copy a reader gets holds it as well, and a wait too short leaves neither a cut nor a time
	closeFlowWaited(t, manager, C.TypeVLESS, "s", 16<<10, 100, false, detectCutWait-time.Second)
	require.Len(t, manager.DetectFlows()["s"].Cuts, 1)
	waited, ok := (&detectStamp{}).waitedAt(time.Now())
	require.False(t, ok)
	require.True(t, waited.IsZero())
}

// The stamp through the counters of a connection: a write of the client after a quiet time sets it,
// the first byte of the server clears it, and the open connection shows it.
func TestDetectStampOfConnection(t *testing.T) {
	manager := NewManager()
	client, lan := net.Pipe()
	defer lan.Close()
	chain := []adapter.Outbound{&detectTestOutbound{outboundType: C.TypeVLESS, tag: "s"}}
	conn := manager.RoutedConnection(context.Background(), client, adapter.InboundContext{OutboundChain: chain}, nil, chain[0])
	stamp := conn.(*connTracker).metadata.stamp
	open := manager.Connections()
	require.Len(t, open, 1)
	metadata := open[0]
	upload := func() {
		go lan.Write([]byte{1})
		_, err := conn.Read(make([]byte, 1))
		require.NoError(t, err)
	}
	download := func() {
		go lan.Read(make([]byte, 1))
		_, err := conn.Write([]byte{1})
		require.NoError(t, err)
	}
	quiet := func() { stamp.lastDownAt.Store(detectClock() - int64(detectPendingGap) - int64(time.Second)) }

	// nothing came yet: the request of a connection is no waiting for the server
	quiet()
	upload()
	require.True(t, metadata.PendingSince().IsZero())
	// the client answers what came at once
	download()
	upload()
	require.True(t, metadata.PendingSince().IsZero())

	quiet()
	before := time.Now()
	upload()
	since := metadata.PendingSince()
	require.False(t, since.IsZero())
	require.WithinDuration(t, before, since, time.Second)
	// it waits since the first write
	stamp.pendingSince.Store(stamp.pendingSince.Load() - int64(time.Hour))
	upload()
	require.WithinDuration(t, before.Add(-time.Hour), metadata.PendingSince(), time.Second)

	download()
	require.True(t, metadata.PendingSince().IsZero())
	require.NoError(t, conn.Close())
}

// Only a TCP connection has a stamp.
func TestDetectStampTCPOnly(t *testing.T) {
	manager := NewManager()
	chain := []adapter.Outbound{&detectTestOutbound{outboundType: C.TypeVLESS, tag: "s"}}
	packet := manager.RoutedPacketConnection(context.Background(), nil, adapter.InboundContext{OutboundChain: chain}, nil, chain[0])
	require.True(t, packet.(*packetConnTracker).metadata.PendingSince().IsZero())
	flow := manager.RoutedFlow(context.Background(), adapter.InboundContext{OutboundChain: chain}, nil, chain[0]).(*flowTracker)
	require.True(t, flow.metadata.PendingSince().IsZero())
}

// LastDataAt is the newest flow opened that got data, not the last close: an old flow that closes
// after a handshake failed says nothing of it.
func TestDetectFlowsLastDataAtIsOpenTime(t *testing.T) {
	manager := NewManager()
	older := openFlow(t, manager, C.TypeVLESS, "s", 100, 100)
	older.metadata.CreatedAt = time.Now().Add(-time.Hour)
	newer := openFlow(t, manager, C.TypeVLESS, "s", 100, 100)
	newer.metadata.CreatedAt = time.Now().Add(-time.Minute)
	empty := openFlow(t, manager, C.TypeVLESS, "s", 0, 100)

	require.NoError(t, older.Close())
	require.True(t, older.metadata.CreatedAt.Equal(manager.DetectFlows()["s"].LastDataAt))
	require.NoError(t, newer.Close())
	require.True(t, newer.metadata.CreatedAt.Equal(manager.DetectFlows()["s"].LastDataAt))

	// neither an older one nor one with nothing moves it back or forward
	late := openFlow(t, manager, C.TypeVLESS, "s", 100, 100)
	late.metadata.CreatedAt = time.Now().Add(-2 * time.Hour)
	require.NoError(t, late.Close())
	require.NoError(t, empty.Close())
	require.True(t, newer.metadata.CreatedAt.Equal(manager.DetectFlows()["s"].LastDataAt))
}

// The outbound of a tag was replaced: what its old connections did is gone, also of those that close
// afterwards, and what the new one carries counts.
func TestForgetDetectFlows(t *testing.T) {
	manager := NewManager()
	closeFlow(t, manager, C.TypeVLESS, "s", DetectBandHigh+1, 100, false)
	closeFlow(t, manager, C.TypeVLESS, "s", DetectBandLow, 100, false)
	closeFlow(t, manager, C.TypeVLESS, "kept", DetectBandLow, 100, false)
	old := openFlow(t, manager, C.TypeVLESS, "s", 16<<10, 100)
	old.metadata.stamp.pendingSince.Store(detectClock() - int64(2*detectCutWait))

	manager.ForgetDetectFlows([]string{"s"})
	samples := manager.DetectFlows()
	require.NotContains(t, samples, "s")
	require.Len(t, samples["kept"].Cuts, 1)

	require.NoError(t, old.Close())
	require.NotContains(t, manager.DetectFlows(), "s")

	closeFlow(t, manager, C.TypeVLESS, "s", DetectBandLow, 100, false)
	sample := manager.DetectFlows()["s"]
	require.Len(t, sample.Cuts, 1)
	require.True(t, sample.LastBigAt.IsZero())
	require.False(t, sample.LastDataAt.IsZero())
}

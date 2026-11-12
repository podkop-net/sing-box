package trafficcontrol

import (
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/compatible"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/cleanup"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/common/x/list"

	"github.com/gofrs/uuid/v5"
)

type ConnectionEventType int

const (
	ConnectionEventNew ConnectionEventType = iota
	ConnectionEventClosed
)

type ConnectionEvent struct {
	Type     ConnectionEventType
	ID       uuid.UUID
	Metadata *TrackerMetadata
	ClosedAt time.Time
}

const closedConnectionsLimit = 1000

var (
	_ adapter.ConnectionTracker = (*Manager)(nil)
	_ adapter.LifecycleService  = (*Manager)(nil)
)

type Manager struct {
	connections             compatible.Map[uuid.UUID, Tracker]
	closedConnectionsAccess sync.Mutex
	closedConnections       list.List[TrackerMetadata]
	closedUploadTotal       int64
	closedDownloadTotal     int64
	// detectFlows is what the block detector reads of the closed TCP connections of the proxy
	// outbounds, by outbound; guarded by closedConnectionsAccess and NOT cleared by Clear()
	// (podkop-engine)
	detectFlows map[string]*DetectFlowSample
	// detectForgotten is when the outbound of a tag was replaced: the flows opened before that are
	// not of what the tag means now (ForgetDetectFlows); guarded by closedConnectionsAccess
	detectForgotten map[string]time.Time

	eventSubscriber *observable.Subscriber[ConnectionEvent]
	eventObserver   *observable.Observer[ConnectionEvent]
}

// A connection that ends with so many bytes received may have been cut, and one above the band
// went past any limit seen on the way (podkop-engine).
const (
	DetectBandLow  = 4 << 10
	DetectBandHigh = 48 << 10

	detectCutsPerOutbound = 16

	detectPendingGap = 5 * time.Second
	detectCutWait    = 3 * time.Second
)

// DetectFlow is a closed connection the block detector may read as cut on the way: it received
// DetectBandLow to DetectBandHigh bytes, the server did not end it, and its client was waiting for
// the server when it closed (detectStamp) (podkop-engine).
type DetectFlow struct {
	Download  int64
	Upload    int64
	CreatedAt time.Time
	ClosedAt  time.Time
	// PendingSince is since when its client had been waiting for the server when it closed, from the
	// same monotonic stamp as TrackerMetadata.PendingSince: the reader asks whether anything came
	// through the outbound after the wait began, which tells a cut from an outage.
	PendingSince time.Time
}

// DetectFlowSample is what the block detector reads of the closed TCP connections of a proxy
// outbound (podkop-engine). Open connections are not here: see Connections.
type DetectFlowSample struct {
	// the last detectCutsPerOutbound possible cuts, the oldest first
	Cuts []DetectFlow
	// when the last connection that went above DetectBandHigh closed
	LastBigAt time.Time
	// when the newest connection that received anything was opened: a connection that closes late
	// says nothing of the handshakes made after it opened
	LastDataAt time.Time
}

func NewManager() *Manager {
	return &Manager{
		detectFlows:     make(map[string]*DetectFlowSample),
		detectForgotten: make(map[string]time.Time),
		eventSubscriber: observable.NewSubscriber[ConnectionEvent](256),
	}
}

func (m *Manager) Name() string {
	return "traffic manager"
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		m.eventObserver = observable.NewObserver(m.eventSubscriber, 64)
		scope.Add(m.eventObserver.Close)
		cleaner := cleanup.Add(m.Clear)
		scope.Add(func() error {
			cleaner.Close()
			return nil
		})
	}
	return nil
}

func (m *Manager) SubscribeEvents() (observable.Subscription[ConnectionEvent], <-chan struct{}, error) {
	return m.eventObserver.Subscribe()
}

func (m *Manager) UnSubscribeEvents(subscription observable.Subscription[ConnectionEvent]) {
	m.eventObserver.UnSubscribe(subscription)
}

func (m *Manager) join(tracker Tracker) {
	metadata := tracker.Metadata()
	m.connections.Store(metadata.ID, tracker)
	m.eventSubscriber.Emit(ConnectionEvent{
		Type:     ConnectionEventNew,
		ID:       metadata.ID,
		Metadata: metadata,
	})
}

func (m *Manager) leave(tracker Tracker) {
	metadata := tracker.Metadata()
	closedAt := time.Now()
	m.closedConnectionsAccess.Lock()
	_, loaded := m.connections.LoadAndDelete(metadata.ID)
	if !loaded {
		m.closedConnectionsAccess.Unlock()
		return
	}
	// The time goes into the copy that is kept, not into the record of the connection
	// itself: that one is being read by whoever lists the connections at this moment (the
	// Clash API copies every record), and the write raced with that read (podkop-engine).
	metadataCopy := *metadata
	metadataCopy.ClosedAt = closedAt
	if m.closedConnections.Len() >= closedConnectionsLimit {
		evicted := m.closedConnections.PopFront()
		m.closedUploadTotal += evicted.Upload.Load()
		m.closedDownloadTotal += evicted.Download.Load()
	}
	m.closedConnections.PushBack(metadataCopy)
	// only the trackers of TCP connections are of this type (podkop-engine)
	if conn, isConn := tracker.(*connTracker); isConn {
		m.recordDetectFlow(metadata, conn.remoteEOF.Load(), closedAt)
	}
	m.closedConnectionsAccess.Unlock()
	m.eventSubscriber.Emit(ConnectionEvent{
		Type:     ConnectionEventClosed,
		ID:       metadata.ID,
		Metadata: &metadataCopy,
		ClosedAt: closedAt,
	})
}

func (m *Manager) Total() (uplinkTotal int64, downlinkTotal int64) {
	m.closedConnectionsAccess.Lock()
	defer m.closedConnectionsAccess.Unlock()
	uplinkTotal = m.closedUploadTotal
	downlinkTotal = m.closedDownloadTotal
	for element := m.closedConnections.Front(); element != nil; element = element.Next() {
		uplinkTotal += element.Value.Upload.Load()
		downlinkTotal += element.Value.Download.Load()
	}
	m.connections.Range(func(_ uuid.UUID, tracker Tracker) bool {
		metadata := tracker.Metadata()
		uplinkTotal += metadata.Upload.Load()
		downlinkTotal += metadata.Download.Load()
		return true
	})
	return
}

func (m *Manager) ConnectionsLen() int {
	return m.connections.Len()
}

func (m *Manager) Connections() []*TrackerMetadata {
	var connections []*TrackerMetadata
	m.connections.Range(func(_ uuid.UUID, tracker Tracker) bool {
		connections = append(connections, tracker.Metadata())
		return true
	})
	return connections
}

func (m *Manager) ClosedConnections() []*TrackerMetadata {
	m.closedConnectionsAccess.Lock()
	values := m.closedConnections.Array()
	m.closedConnectionsAccess.Unlock()
	if len(values) == 0 {
		return nil
	}
	connections := make([]*TrackerMetadata, len(values))
	for i := range values {
		connections[i] = &values[i]
	}
	return connections
}

func (m *Manager) Connection(id uuid.UUID) Tracker {
	connection, loaded := m.connections.Load(id)
	if !loaded {
		return nil
	}
	return connection
}

func (m *Manager) CloseAllConnections() {
	m.connections.Range(func(_ uuid.UUID, tracker Tracker) bool {
		tracker.Close()
		return true
	})
}

// recordDetectFlow adds a closed TCP connection to what the block detector reads. The caller holds
// closedConnectionsAccess.
func (m *Manager) recordDetectFlow(metadata *TrackerMetadata, remoteEOF bool, closedAt time.Time) {
	if metadata.OutboundType == C.TypeDirect || metadata.OutboundType == C.TypeBlock {
		return
	}
	if forgotten, isForgotten := m.detectForgotten[metadata.Outbound]; isForgotten && metadata.CreatedAt.Before(forgotten) {
		return
	}
	download := metadata.Download.Load()
	if download == 0 {
		return
	}
	sample := m.detectFlows[metadata.Outbound]
	if sample == nil {
		sample = new(DetectFlowSample)
		m.detectFlows[metadata.Outbound] = sample
	}
	if metadata.CreatedAt.After(sample.LastDataAt) {
		sample.LastDataAt = metadata.CreatedAt
	}
	switch {
	case download > DetectBandHigh:
		sample.LastBigAt = closedAt
	case download >= DetectBandLow && !remoteEOF:
		pendingSince, waited := metadata.stamp.waitedAt(closedAt)
		if !waited {
			return
		}
		if len(sample.Cuts) >= detectCutsPerOutbound {
			sample.Cuts = append(sample.Cuts[:0], sample.Cuts[1:]...)
		}
		sample.Cuts = append(sample.Cuts, DetectFlow{
			Download:     download,
			Upload:       metadata.Upload.Load(),
			CreatedAt:    metadata.CreatedAt,
			ClosedAt:     closedAt,
			PendingSince: pendingSince,
		})
	}
}

// DetectFlows returns what the block detector reads of the closed TCP connections, by outbound
// tag (podkop-engine). Unlike ClosedConnections it is not wiped by Clear(). The tags of outbounds
// gone stay; the reader asks for the ones it knows.
func (m *Manager) DetectFlows() map[string]DetectFlowSample {
	m.closedConnectionsAccess.Lock()
	defer m.closedConnectionsAccess.Unlock()
	samples := make(map[string]DetectFlowSample, len(m.detectFlows))
	for tag, sample := range m.detectFlows {
		copied := *sample
		copied.Cuts = slices.Clone(sample.Cuts)
		samples[tag] = copied
	}
	return samples
}

// ForgetDetectFlows drops what the block detector reads of the tags, whose outbounds were replaced
// while the manager stays (podkop-engine): the old outbounds keep their connections, and those are
// not counted when they close either. A tag takes one small entry for good.
func (m *Manager) ForgetDetectFlows(tags []string) {
	now := time.Now()
	m.closedConnectionsAccess.Lock()
	defer m.closedConnectionsAccess.Unlock()
	for _, tag := range tags {
		delete(m.detectFlows, tag)
		m.detectForgotten[tag] = now
	}
}

func (m *Manager) Clear() {
	m.closedConnectionsAccess.Lock()
	defer m.closedConnectionsAccess.Unlock()
	for element := m.closedConnections.Front(); element != nil; element = element.Next() {
		m.closedUploadTotal += element.Value.Upload.Load()
		m.closedDownloadTotal += element.Value.Download.Load()
	}
	m.closedConnections.Init()
}

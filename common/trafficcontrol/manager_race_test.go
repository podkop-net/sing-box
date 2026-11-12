package trafficcontrol

import (
	"sync/atomic"
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

type recordTracker struct {
	metadata TrackerMetadata
}

func (t *recordTracker) Metadata() *TrackerMetadata { return &t.metadata }
func (t *recordTracker) Close() error               { return nil }

// A connection that closes while the connections are being listed: the record of the
// connection is read by the one who lists (the Clash API copies each), so the closing
// writes its time into the copy it keeps and not into that record. With the race detector
// this test is the race itself.
func TestLeaveDoesNotWriteTheRecordBeingRead(t *testing.T) {
	manager := NewManager()
	var read int64
	for range 100 {
		tracker := &recordTracker{metadata: TrackerMetadata{ID: uuid.Must(uuid.NewV4()), Upload: new(atomic.Int64), Download: new(atomic.Int64)}}
		manager.join(tracker)
		listed := make(chan struct{})
		go func() {
			defer close(listed)
			for _, metadata := range manager.Connections() {
				record := *metadata
				atomic.AddInt64(&read, record.ClosedAt.Unix())
			}
		}()
		manager.leave(tracker)
		<-listed
		require.True(t, tracker.metadata.ClosedAt.IsZero(), "the record of the connection was written to")
	}
	closed := manager.ClosedConnections()
	require.Len(t, closed, 100)
	for _, metadata := range closed {
		require.False(t, metadata.ClosedAt.IsZero(), "the record that is kept has no closing time")
	}
}

package trafficontrol

import (
	"errors"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	"github.com/stretchr/testify/require"
)

// The tracker's copy of the metadata drops the sniffer's state; the caller's metadata keeps
// it, and what the connection list shows stays.
func TestTrimTrackedMetadata(t *testing.T) {
	original := adapter.InboundContext{
		Protocol:     "quic",
		Domain:       "example.com",
		SniffContext: make([]byte, 4096),
		SniffError:   errors.New("need more packets"),
	}
	tracked := original
	trimTrackedMetadata(&tracked)
	require.Nil(t, tracked.SniffContext)
	require.NoError(t, tracked.SniffError)
	require.Equal(t, "quic", tracked.Protocol)
	require.Equal(t, "example.com", tracked.Domain)
	require.NotNil(t, original.SniffContext)
	require.Error(t, original.SniffError)
}

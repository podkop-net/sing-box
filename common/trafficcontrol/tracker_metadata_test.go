package trafficcontrol

import (
	"errors"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// The tracker's copy of the metadata drops the sniffer's state and the DNS answers; the
// caller's metadata keeps them, and what the connection list shows stays.
func TestTrimTrackedMetadata(t *testing.T) {
	original := adapter.InboundContext{
		Protocol:          "quic",
		Domain:            "example.com",
		SniffContext:      make([]byte, 4096),
		SniffError:        errors.New("need more packets"),
		DNSResponse:       new(mDNS.Msg),
		NamedDNSResponses: map[string]*mDNS.Msg{"a": new(mDNS.Msg)},
	}
	tracked := original
	trimTrackedMetadata(&tracked)
	require.Nil(t, tracked.SniffContext)
	require.NoError(t, tracked.SniffError)
	require.Nil(t, tracked.DNSResponse)
	require.Nil(t, tracked.NamedDNSResponses)
	require.Equal(t, "quic", tracked.Protocol)
	require.Equal(t, "example.com", tracked.Domain)
	require.NotNil(t, original.SniffContext)
	require.Error(t, original.SniffError)
	require.NotNil(t, original.DNSResponse)
	require.Len(t, original.NamedDNSResponses, 1)
}

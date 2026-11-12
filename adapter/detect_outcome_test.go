package adapter

import (
	"testing"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// The form of the key is that of the records in the cache files.
func TestDetectOutcomeKey(t *testing.T) {
	require.Equal(t, "chrome www.example.com 192.0.2.1:443", DetectOutcomeKey("chrome", "www.example.com", M.ParseSocksaddrHostPort("192.0.2.1", 443)))
	require.Equal(t, "chrome www.example.com 192.0.2.1:443", DetectOutcomeKey("", "www.example.com", M.ParseSocksaddrHostPort("192.0.2.1", 443)))
	require.Equal(t, "edge srv.example.com srv.example.com:8443", DetectOutcomeKey("edge", "srv.example.com", M.ParseSocksaddrHostPort("srv.example.com", 8443)))
	require.Equal(t, "firefox a.example.com [2001:db8::1]:443", DetectOutcomeKey("firefox", "a.example.com", M.ParseSocksaddr("[2001:db8::1]:443")))
}

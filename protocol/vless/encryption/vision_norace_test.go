//go:build !race

package encryption

import (
	"net"
	"testing"

	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// Vision takes this layer as the one under it, and a plain TCP connection still not.
// Not under the race detector: it turns on checkptr, which stops at the pointer
// arithmetic of NewVisionConn with any connection, a TLS one as well.
func TestVisionTakesTheLayer(t *testing.T) {
	t.Parallel()
	serverKey, clientKey := testKeys(t, "x25519")
	server := newTestServer(t, [][]byte{serverKey}, 0, 0, "")
	client, err := NewClient(Prefix + ".native.1rtt." + clientKey)
	require.NoError(t, err)
	encrypted := server.dial(t, client)
	_, err = vless.NewVisionConn(encrypted, encrypted, [16]byte{}, logger.NOP())
	require.NoError(t, err)

	plain, err := net.Dial("tcp", server.listener.Addr().String())
	require.NoError(t, err)
	defer plain.Close()
	_, err = vless.NewVisionConn(plain, plain, [16]byte{}, logger.NOP())
	require.ErrorContains(t, err, "not a valid supported TLS connection")
}

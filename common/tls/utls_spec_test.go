//go:build with_utls

package tls

import (
	"bytes"
	"net"
	"runtime"
	"testing"
	"testing/cryptotest"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

var specFingerprints = []string{"chrome", "edge", "ios", "qq", "360", "android"}

// A hello built from the specification of a fingerprint is, byte for byte, the hello uTLS
// builds from the fingerprint's ID: the same random stream gives the same bytes, the
// shuffled extension order of Chrome included.
func TestNewUClientHelloUnchanged(t *testing.T) {
	// a key share made from a caller's random source reads, at random, one byte more of it
	// (the Go version of the module keeps that behavior): two hellos by ID then differ
	t.Setenv("GODEBUG", "cryptocustomrand=0")
	for _, name := range specFingerprints {
		id, err := uTLSClientHelloID(name)
		require.NoError(t, err, name)
		build := func(create func(conn net.Conn, config *utls.Config) *utls.UConn) []byte {
			cryptotest.SetGlobalRandom(t, 20261008)
			uConn := create(nil, &utls.Config{ServerName: "example.com", NextProtos: []string{"h2", "http/1.1"}})
			require.NoError(t, uConn.BuildHandshakeState(), name)
			return uConn.HandshakeState.Hello.Raw
		}
		makeByID := func(conn net.Conn, config *utls.Config) *utls.UConn {
			return utls.UClient(conn, config, id)
		}
		makeBySpec := func(conn net.Conn, config *utls.Config) *utls.UConn {
			uConn, err := newUClient(conn, config, id)
			require.NoError(t, err, name)
			return uConn
		}
		byID := build(makeByID)
		require.NotEmpty(t, byID, name)
		for range 8 {
			again := build(makeByID)
			require.True(t, bytes.Equal(byID, again), "%s: the test is not deterministic, two hellos by ID differ: %d and %d bytes, first difference at byte %d", name, len(byID), len(again), firstDifference(byID, again))
			bySpec := build(makeBySpec)
			require.True(t, bytes.Equal(byID, bySpec), "%s: the hello differs: %d bytes by ID, %d by specification, first difference at byte %d", name, len(byID), len(bySpec), firstDifference(byID, bySpec))
		}
	}
}

func firstDifference(a []byte, b []byte) int {
	first := 0
	for first < len(a) && first < len(b) && a[first] == b[first] {
		first++
	}
	return first
}

// Once the handshake state is released, a connection made from the specification no longer
// holds the extension objects, which one made by ID does: for chrome that is the
// X25519MLKEM768 key share alone, 1216 bytes.
func TestNewUClientSpecReleased(t *testing.T) {
	const connections = 2000
	held := func(name string, create func(config *utls.Config) *utls.UConn) int {
		conns := make([]*utls.UConn, connections)
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for i := range conns {
			uConn := create(&utls.Config{ServerName: "example.com", NextProtos: []string{"h2", "http/1.1"}})
			require.NoError(t, uConn.BuildHandshakeState(), name)
			releaseHandshakeState(uConn)
			conns[i] = uConn
		}
		runtime.GC()
		runtime.GC()
		runtime.ReadMemStats(&after)
		runtime.KeepAlive(conns)
		return (int(after.HeapAlloc) - int(before.HeapAlloc)) / connections
	}
	for _, name := range specFingerprints {
		id, err := uTLSClientHelloID(name)
		require.NoError(t, err, name)
		byID := held(name, func(config *utls.Config) *utls.UConn {
			return utls.UClient(nil, config, id)
		})
		bySpec := held(name, func(config *utls.Config) *utls.UConn {
			uConn, err := newUClient(nil, config, id)
			require.NoError(t, err, name)
			return uConn
		})
		t.Logf("%s: %d bytes held per connection by ID, %d by specification, %d less", name, byID, bySpec, byID-bySpec)
		require.Less(t, bySpec, byID, name)
		if name == "chrome" {
			require.GreaterOrEqual(t, byID-bySpec, 1216, name)
		}
	}
}

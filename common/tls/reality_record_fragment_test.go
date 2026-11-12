//go:build with_utls

package tls

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// helloRecords reads the TLS records a client writes up to the end of its ClientHello and
// returns their payload lengths and the length of the ClientHello message (4-byte handshake
// header included).
func helloRecords(t *testing.T, server net.Conn) (records []int, hello int) {
	t.Helper()
	require.NoError(t, server.SetReadDeadline(time.Now().Add(10*time.Second)))
	got := 0
	for hello == 0 || got < hello {
		header := make([]byte, 5)
		_, err := io.ReadFull(server, header)
		require.NoError(t, err)
		require.Equal(t, byte(0x16), header[0], "a handshake record")
		payload := make([]byte, binary.BigEndian.Uint16(header[3:5]))
		_, err = io.ReadFull(server, payload)
		require.NoError(t, err)
		if hello == 0 {
			require.Equal(t, byte(0x01), payload[0], "the record starts with a ClientHello")
			hello = 4 + int(payload[1])<<16 + int(payload[2])<<8 + int(payload[3])
		}
		records = append(records, len(payload))
		got += len(payload)
	}
	require.Equal(t, hello, got, "the records carry exactly the ClientHello")
	return records, hello
}

// record_fragment splits the ClientHello of a REALITY client into several TLS records, as it
// does for a uTLS client; without it the ClientHello is one record (podkop-engine).
func TestRealityRecordFragment(t *testing.T) {
	for _, fragment := range []bool{false, true} {
		logger, _ := newWarnLogger(t)
		options := realityOptionsForTest("chrome", true)
		options.RecordFragment = fragment
		config, err := NewClient(context.Background(), logger, "192.0.2.1", options)
		require.NoError(t, err)
		_, isReality := config.(*RealityClientConfig)
		require.True(t, isReality)

		client, server := net.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		done := make(chan struct{})
		go func() {
			defer close(done)
			// the handshake fails once the test closes the server end: only the hello matters
			_, _ = ClientHandshake(ctx, client, config.Clone())
		}()
		records, hello := helloRecords(t, server)
		server.Close()
		<-done
		cancel()
		client.Close()

		if fragment {
			require.Greater(t, len(records), 1, "record_fragment splits the ClientHello")
			for _, length := range records {
				require.Less(t, length, hello)
			}
		} else {
			require.Equal(t, []int{hello}, records, "one record without record_fragment")
		}
	}
}

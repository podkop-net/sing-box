package dialer

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// The finalmask of the dialer options reaches the TCP connections of the default dialer: a
// ClientHello written to one arrives cut into records of the lengths asked for.
func TestDefaultDialerFinalMask(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		content, _ := io.ReadAll(conn)
		received <- content
	}()
	length := option.V2RayXHTTPRange{From: 11, To: 24}
	dialer, err := NewDefault(context.Background(), option.DialerOptions{FinalMask: &option.FinalMaskOptions{
		TCP: []option.FinalMaskTCPOptions{{Type: "fragment", Packets: "tlshello", Length: &length}},
	}})
	require.NoError(t, err)
	conn, err := dialer.DialContext(context.Background(), "tcp", M.ParseSocksaddr(listener.Addr().String()))
	require.NoError(t, err)
	payload := make([]byte, 600)
	_, _ = rand.Read(payload)
	payload[0] = 1
	message := append([]byte{22, 3, 1, byte(len(payload) >> 8), byte(len(payload))}, payload...)
	_, err = conn.Write(message)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	stream := <-received
	var joined []byte
	count := 0
	for len(stream) >= 5 {
		size := int(stream[3])<<8 | int(stream[4])
		require.LessOrEqual(t, size, 24)
		joined = append(joined, stream[5:5+size]...)
		stream = stream[5+size:]
		count++
	}
	require.Empty(t, stream)
	require.Equal(t, payload, joined)
	require.Greater(t, count, 600/24)
}

// Without a finalmask the bytes go as they are written.
func TestDefaultDialerWithoutFinalMask(t *testing.T) {
	t.Parallel()
	dialer, err := NewDefault(context.Background(), option.DialerOptions{})
	require.NoError(t, err)
	require.Nil(t, dialer.finalMask)
}

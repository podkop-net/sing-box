package tls

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"github.com/stretchr/testify/require"
)

// handshakeRecorder stands for a TLS client config and records the context its handshake
// gets.
type handshakeRecorder struct {
	Config
	deadline    time.Time
	hasDeadline bool
}

func (c *handshakeRecorder) ClientHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	c.deadline, c.hasDeadline = ctx.Deadline()
	return nil, os.ErrInvalid
}

// A proxied connection's context has no deadline: the dialer still bounds the handshake,
// or a server that accepts the connection and never answers would keep the dial forever.
func TestDialerBoundsHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()
	config := &handshakeRecorder{}
	_, err = NewDialer(N.SystemDialer, config).DialTLSContext(context.Background(), M.SocksaddrFromNet(listener.Addr()))
	require.Error(t, err)
	require.True(t, config.hasDeadline, "the handshake has no deadline")
	require.WithinDuration(t, time.Now().Add(C.TCPTimeout), config.deadline, time.Second)
}

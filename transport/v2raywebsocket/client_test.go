package v2raywebsocket

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/ws"

	"github.com/stretchr/testify/require"
)

func testClient(t *testing.T, serve func(conn net.Conn)) adapter.V2RayClientTransport {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				serve(conn)
			}()
		}
	}()
	client, err := NewClient(context.Background(), N.SystemDialer, M.SocksaddrFromNet(listener.Addr()), option.V2RayWebsocketOptions{Path: "/"}, nil)
	require.NoError(t, err)
	return client
}

// A server that takes the request and never answers: the dial ends with its context, not at the
// fixed deadline of the upgrade, or a caller that holds a lock across it (the probe of the block
// detector) blocks whoever waits for that lock.
func TestDialEndsWithItsContext(t *testing.T) {
	client := testClient(t, func(conn net.Conn) { io.Copy(io.Discard, conn) })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		conn, err := client.DialContext(ctx)
		if err == nil {
			conn.Close()
		}
		result <- err
	}()
	select {
	case err := <-result:
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("the upgrade outlived the context of its dial")
	}
}

// A healthy upgraded connection does not die with the context of its dial.
func TestUpgradedConnectionOutlivesItsDialContext(t *testing.T) {
	send := make(chan struct{})
	client := testClient(t, func(conn net.Conn) {
		_, err := ws.Upgrade(conn)
		if err != nil {
			t.Error(err)
			return
		}
		<-send
		err = ws.WriteFrame(conn, ws.NewBinaryFrame([]byte("late")))
		if err != nil {
			t.Error(err)
			return
		}
		io.Copy(io.Discard, conn)
	})
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := client.DialContext(ctx)
	require.NoError(t, err)
	defer conn.Close()
	cancel()
	time.Sleep(50 * time.Millisecond)
	close(send)
	// this connection has no read deadline
	read := make(chan string, 1)
	go func() {
		data := make([]byte, len("late"))
		_, err := io.ReadFull(conn, data)
		if err != nil {
			read <- err.Error()
			return
		}
		read <- string(data)
	}()
	select {
	case data := <-read:
		require.Equal(t, "late", data)
	case <-time.After(3 * time.Second):
		t.Fatal("nothing came through the upgraded connection")
	}
	_, err = conn.Write([]byte("more"))
	require.NoError(t, err)
}

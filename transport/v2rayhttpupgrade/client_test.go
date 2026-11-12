package v2rayhttpupgrade

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func testClient(t *testing.T, serve func(conn net.Conn)) *Client {
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
	client, err := NewClient(context.Background(), N.SystemDialer, M.SocksaddrFromNet(listener.Addr()), option.V2RayHTTPUpgradeOptions{Path: "/"}, nil)
	require.NoError(t, err)
	return client
}

// A server that takes the request and never answers: the dial ends with its context, or a caller
// that holds a lock across it (the probe of the block detector) blocks whoever waits for that lock.
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

// A healthy upgraded connection does not die with the context of its dial, what came with the
// answer included.
func TestUpgradedConnectionOutlivesItsDialContext(t *testing.T) {
	send := make(chan struct{})
	client := testClient(t, func(conn net.Conn) {
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			t.Error(err)
			return
		}
		request.Body.Close()
		_, err = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\nearly")
		if err != nil {
			t.Error(err)
			return
		}
		<-send
		_, err = io.WriteString(conn, "late")
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
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	data := make([]byte, len("earlylate"))
	_, err = io.ReadFull(conn, data)
	require.NoError(t, err)
	require.Equal(t, "earlylate", string(data))
	_, err = conn.Write([]byte("more"))
	require.NoError(t, err)
}

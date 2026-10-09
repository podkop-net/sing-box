package tf

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A piece that is never acknowledged does not keep the connection from being closed, and
// the close ends the wait for the acknowledgment: this is how the handshake timeout ends
// a fragmented ClientHello that a middlebox drops. Needs root and nft, in a network
// namespace of its own (a container).
func TestIntegrationWaitAckGivesWayToClose(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root and nft")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(io.Discard, conn)
				conn.Close()
			}()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	// dropped on the way in: on the way out the packet would not count as sent
	table := fmt.Sprintf("tfwait%d", port)
	command := exec.Command("nft", "-f", "-")
	command.Stdin = strings.NewReader(fmt.Sprintf("add table inet %s\nadd chain inet %s input { type filter hook input priority 0; }\nadd rule inet %s input tcp dport %d meta length > 100 counter drop\n", table, table, table, port))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Skip("nft: ", err, ": ", string(output))
	}
	defer exec.Command("nft", "delete", "table", "inet", table).Run()

	conn, err := net.Dial("tcp4", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	waited := make(chan error, 1)
	go func() {
		waited <- writeAndWaitAck(context.Background(), conn.(*net.TCPConn), make([]byte, 600), time.Millisecond)
	}()
	select {
	case err = <-waited:
		t.Fatal("the wait ended though the piece was not acknowledged: ", err)
	case <-time.After(300 * time.Millisecond):
	}
	closed := make(chan struct{})
	go func() {
		conn.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the close waits for the piece to be acknowledged")
	}
	select {
	case err = <-waited:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("the wait goes on after the connection was closed")
	}
}

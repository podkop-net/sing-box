package v2rayxhttp

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// Many sessions held at once, each carrying a little data: the load of a busy
// network, where the HTTP/2 client spreads the streams over more connections.
func TestXHTTPManySessions(t *testing.T) {
	for _, mode := range []string{modePacketUp, modeStreamUp, modeStreamOne} {
		t.Run(mode, func(t *testing.T) {
			options := option.V2RayXHTTPOptions{Mode: mode}
			// connections rotate many times while the sessions are open
			options.Xmux = &option.V2RayXHTTPXmuxOptions{
				MaxConnections:   &option.V2RayXHTTPRange{From: 3, To: 3},
				HMaxRequestTimes: &option.V2RayXHTTPRange{From: 40, To: 40},
			}
			client, _ := newTestPair(t, options, "h2", nil)
			const sessions = 300
			var (
				group  sync.WaitGroup
				access sync.Mutex
				failed []string
				conns  []net.Conn
			)
			limit := make(chan struct{}, 20)
			for i := 0; i < sessions; i++ {
				group.Add(1)
				limit <- struct{}{}
				go func(i int) {
					defer group.Done()
					defer func() { <-limit }()
					conn, err := client.DialContext(context.Background())
					if err != nil {
						access.Lock()
						failed = append(failed, "dial: "+err.Error())
						access.Unlock()
						return
					}
					access.Lock()
					conns = append(conns, conn)
					access.Unlock()
					// two writes, as a proxied request makes: the header of the
					// protocol above, then the payload
					conn.Write([]byte{byte(i)})
					conn.Write([]byte{byte(i >> 8), 7})
					reply := make([]byte, 3)
					conn.SetReadDeadline(time.Now().Add(10 * time.Second))
					done := make(chan error, 1)
					go func() {
						_, err := io.ReadFull(conn, reply)
						done <- err
					}()
					select {
					case err = <-done:
					case <-time.After(10 * time.Second):
						err = context.DeadlineExceeded
					}
					if err != nil {
						access.Lock()
						failed = append(failed, "echo: "+err.Error())
						access.Unlock()
					}
				}(i)
			}
			group.Wait()
			for _, conn := range conns {
				conn.Close()
			}
			require.Empty(t, failed, "%d of %d sessions failed", len(failed), sessions)
		})
	}
}

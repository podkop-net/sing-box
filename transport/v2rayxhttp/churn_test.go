package v2rayxhttp

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// Sessions opened and closed many at a time all work: on HTTP/1.1 a cancelled
// upload request used to close the connection the next upload had taken.
func TestXHTTPChurn(t *testing.T) {
	for _, version := range []string{"h1", "h1-tls", "h2"} {
		t.Run(version, func(t *testing.T) {
			client, _ := newTestPair(t, option.V2RayXHTTPOptions{Mode: modePacketUp}, version, nil)
			var failures atomic.Int32
			var first sync.Once
			var wg sync.WaitGroup
			for worker := 0; worker < 20; worker++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < 200; i++ {
						conn, err := client.DialContext(context.Background())
						if err == nil {
							_, err = conn.Write([]byte("0123456789abcdef"))
						}
						if err == nil {
							_, err = io.ReadFull(conn, make([]byte, 16))
						}
						if conn != nil {
							conn.Close()
						}
						if err != nil {
							failures.Add(1)
							first.Do(func() { t.Log("first failure: ", err) })
						}
					}
				}()
			}
			wg.Wait()
			require.Zero(t, failures.Load(), "sessions failed")
		})
	}
}

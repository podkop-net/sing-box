//go:build linux

package probesock

import (
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The window of a probe connection that a multiplexed transport keeps for other traffic grows
// again once the probe is done; left as the probe had it, it holds the traffic to some 16 KB a
// round trip. Needs a delay on the loopback (PROBESOCK_NETEM=1 after
// "tc qdisc add dev lo root netem delay 12ms"); skipped otherwise.
func TestWindowGrowsAfterProbe(t *testing.T) {
	if os.Getenv("PROBESOCK_NETEM") == "" {
		t.Skip("needs a delay on lo: tc qdisc add dev lo root netem delay 12ms, PROBESOCK_NETEM=1")
	}
	const after = 16 << 20
	address := serve(t, LossProbeSizeForTest+after)
	rate := func(restore bool) float64 {
		ctx, socket := With(context.Background(), Window)
		conn, err := socket.Dial(ctx, net.Dialer{}, "tcp", address)
		require.NoError(t, err)
		defer conn.Close()
		_, err = conn.Write([]byte{1})
		require.NoError(t, err)
		_, err = io.CopyN(io.Discard, conn, LossProbeSizeForTest)
		require.NoError(t, err)
		if restore {
			_, err = socket.Finish()
			require.NoError(t, err)
		} else {
			// the probe as it was before: the capture ends, the window stays
			socket.access.Lock()
			socket.capture.stop()
			socket.capture = nil
			socket.restored = true
			socket.access.Unlock()
		}
		start := time.Now()
		received, err := io.CopyN(io.Discard, conn, after)
		require.NoError(t, err)
		return float64(received) * 8 / time.Since(start).Seconds() / 1e6
	}
	kept, restored := rate(false), rate(true)
	t.Logf("after the probe: %.1f Mbit/s with the window of the probe, %.1f Mbit/s with it restored", kept, restored)
	require.Greater(t, restored, 4*kept)
}

// LossProbeSizeForTest is what the probe reads before the traffic goes on.
const LossProbeSizeForTest = 256 << 10

package urltest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/probesock"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

// probeDialer dials as an outbound over the default dialer does: the first dial under a probe
// context is the probe connection.
type probeDialer struct{}

func (probeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if socket := probesock.From(ctx); socket != nil {
		return socket.Dial(ctx, net.Dialer{}, network, destination.String())
	}
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

func (probeDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("no UDP")
}

func skipWithoutCapture(t *testing.T, err error) {
	if err != nil && strings.Contains(err.Error(), "operation not permitted") {
		t.Skip("no CAP_NET_RAW: ", err)
	}
}

// A body cut by the time limit while it still comes is counted as far as it came; one that
// brings nothing for lossStall is stopped.
func TestLossProbeSlowAndStalled(t *testing.T) {
	timeout, stall := lossClientTimeout, lossStall
	lossClientTimeout, lossStall = time.Second, 300*time.Millisecond
	t.Cleanup(func() { lossClientTimeout, lossStall = timeout, stall })
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(LossProbeLarge))
		for sent := 0; sent < LossProbeLarge; sent += 8 << 10 {
			if _, err := w.Write(make([]byte, 8<<10)); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
		}
	}))
	t.Cleanup(slow.Close)
	sample, err := LossProbe(context.Background(), slow.URL, LossProbeLarge, probeDialer{})
	skipWithoutCapture(t, err)
	require.NoError(t, err)
	require.Less(t, sample.Received, int64(LossProbeLarge))
	require.Positive(t, sample.Segments)
	require.Zero(t, sample.Lost)
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(LossProbeLarge))
		w.Write(make([]byte, 64<<10))
		w.(http.Flusher).Flush()
		time.Sleep(3 * time.Second)
	}))
	t.Cleanup(stalled.Close)
	_, err = LossProbe(context.Background(), stalled.URL, LossProbeLarge, probeDialer{})
	require.ErrorIs(t, err, ErrDownloadStopped)
}

// A probe that went over no connection of its own is told so: it will not be counted.
func TestLossProbeNotOwnConnection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, LossProbeSmall))
	}))
	t.Cleanup(server.Close)
	plain := DialerFunc(func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, destination.String())
	})
	_, err := LossProbe(context.Background(), server.URL, LossProbeSmall, plain)
	require.ErrorIs(t, err, ErrLossNotCounted)
	require.ErrorIs(t, err, ErrLossNotOwnConnection)
}

// DialerFunc is a dialer of a function, for the tests.
type DialerFunc func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)

func (f DialerFunc) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return f(ctx, network, destination)
}

func (f DialerFunc) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("no UDP")
}

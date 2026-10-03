package rule

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// testDialer dials the loopback test server directly.
type testDialer struct{}

func (testDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

func (testDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, "udp", ":0")
}

func newTestRuleSet(url string) *RemoteRuleSet {
	return &RemoteRuleSet{
		ctx:    context.Background(),
		logger: log.NewNOPFactory().NewLogger("test"),
		dialer: testDialer{},
		options: option.RuleSet{
			Tag:           "test",
			RemoteOptions: option.RemoteRuleSet{URL: url},
		},
	}
}

// A download that sends its headers and then goes silent must not hold the caller: the stall
// timer ends it. At start this is the difference between the LAN getting DNS after a bounded
// wait and having no DNS until the TCP connection dies (about 16 minutes).
func TestRemoteRuleSetFetchStalls(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-release // headers sent, then no body bytes ever
	}))
	defer server.Close()
	defer close(release)

	defer swapTimeouts(50*time.Millisecond, time.Hour)()
	set := newTestRuleSet(server.URL)

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- set.fetch(context.Background(), nil) }()
	select {
	case err := <-done:
		require.Error(t, err)
		require.Less(t, time.Since(start), 2*time.Second)
	case <-time.After(5 * time.Second):
		t.Fatal("fetch did not return after the stall timeout")
	}
}

// The point of the stall timer over a total deadline: a slow but STEADY download, whose total
// time far exceeds the stall timeout, must still succeed. A big list on a slow router link is
// exactly this case. The old total-deadline algorithm failed it.
func TestRemoteRuleSetFetchSlowButSteady(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		flusher := w.(http.Flusher)
		for i := 0; i < 20; i++ {
			w.Write([]byte(strings.Repeat("x", 256)))
			flusher.Flush()
			time.Sleep(40 * time.Millisecond)
		}
	}))
	defer server.Close()

	defer swapTimeouts(200*time.Millisecond, 200*time.Millisecond)()
	set := newTestRuleSet(server.URL)

	// loadBytes rejects the body as a non-rule-set, but the fetch must get PAST the read
	// (reach parsing) rather than time out mid-transfer.
	err := set.fetch(context.Background(), nil)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "context") // not a deadline/stall cancellation
}

// A body larger than any real rule-set is refused instead of being read into memory without
// bound.
func TestRemoteRuleSetFetchSizeCap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		chunk := strings.Repeat("A", 1<<20)
		for range (ruleSetMaxSize >> 20) + 2 {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
			flusher.Flush()
		}
	}))
	defer server.Close()

	set := newTestRuleSet(server.URL)
	err := set.fetch(context.Background(), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "larger than")
}

func swapTimeouts(stall, startDeadline time.Duration) func() {
	oldStall, oldStart := ruleSetStallTimeout, ruleSetStartDeadline
	ruleSetStallTimeout, ruleSetStartDeadline = stall, startDeadline
	return func() { ruleSetStallTimeout, ruleSetStartDeadline = oldStall, oldStart }
}

var _ N.Dialer = testDialer{}

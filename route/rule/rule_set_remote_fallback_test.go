package rule

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

// refusingClient is a way that cannot reach the server: its dial fails with err.
func refusingClient(err error) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, err
		},
	}}
}

// A list the client of the rule-set cannot download comes through the first fallback client that
// can; the clients after it are not asked.
func TestRemoteRuleSetFetchFallback(t *testing.T) {
	var asked atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		io.WriteString(w, testSourceSet)
	}))
	defer server.Close()
	var lastAsked atomic.Bool
	last := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			lastAsked.Store(true)
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}}
	set := newTestRuleSet(server.URL)
	set.options.Format = C.RuleSetFormatSource
	set.httpClient = refusingClient(errors.New("direct refused"))
	set.fallbacks = []ruleSetFallback{
		{tag: "dead", client: refusingClient(errors.New("dead refused"))},
		{tag: "via-a", client: &http.Client{Transport: &http.Transport{}}},
		{tag: "via-b", client: last},
	}
	require.NoError(t, set.fetch(context.Background(), false))
	require.Len(t, set.currentRules(), 1)
	require.EqualValues(t, 1, asked.Load())
	require.False(t, lastAsked.Load())
}

// A way that sends its headers and then goes silent is left after the stall timeout, and the next
// way has the whole timeout of its own.
func TestRemoteRuleSetFetchFallbackAfterStall(t *testing.T) {
	defer swapTimeouts(200*time.Millisecond, time.Minute)()
	release := make(chan struct{})
	var stalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stalled.CompareAndSwap(false, true) {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-release
			return
		}
		io.WriteString(w, testSourceSet)
	}))
	defer server.Close()
	// before the server closes: Close waits for the handler that holds the stalled answer
	defer close(release)
	set := newTestRuleSet(server.URL)
	set.options.Format = C.RuleSetFormatSource
	set.httpClient = &http.Client{Transport: &http.Transport{}}
	set.fallbacks = []ruleSetFallback{{tag: "via-a", client: &http.Client{Transport: &http.Transport{}}}}
	require.NoError(t, set.fetch(context.Background(), false))
	require.Len(t, set.currentRules(), 1)
}

// When no way brings the list, the error tells what each of them met.
func TestRemoteRuleSetFetchFallbackAllFail(t *testing.T) {
	set := newTestRuleSet("http://lists.invalid/list.json")
	set.options.Format = C.RuleSetFormatSource
	set.httpClient = refusingClient(errors.New("direct refused"))
	set.fallbacks = []ruleSetFallback{
		{tag: "via-a", client: refusingClient(errors.New("a refused"))},
		{tag: "via-b", client: refusingClient(errors.New("b refused"))},
	}
	err := set.fetch(context.Background(), false)
	require.Error(t, err)
	for _, text := range []string{"direct refused", "http_client[via-a]", "a refused", "http_client[via-b]", "b refused"} {
		require.Contains(t, err.Error(), text)
	}
	require.Empty(t, set.currentRules())
}

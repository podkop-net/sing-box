package rule_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/httpclient"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/route/rule"

	"github.com/stretchr/testify/require"
)

const downloaderList = `{"version":3,"rules":[{"domain_suffix":["example.com"]}]}`

// testWay is an http.Transport as the transport of a way of a downloader.
type testWay struct{ *http.Transport }

func (w testWay) Reset() { w.CloseIdleConnections() }

// wayTo is a way that reaches address whatever the request names: the way of an ISP that answers
// a blocked address with its own page.
func wayTo(address string) testWay {
	return testWay{&http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}}
}

func testRuleSetDownloader(ways []string, transports map[string]adapter.HTTPTransport) *httpclient.Downloader {
	downloader := httpclient.NewDownloader(log.NewNOPFactory().Logger(), ways, transports, nil, nil)
	downloader.Plan = httpclient.DownloadPlan{Wait: 50 * time.Millisecond, Body: 30 * time.Millisecond, LargeBody: 300 * time.Millisecond, Large: 1 << 20, Most: 3}
	return downloader
}

// A page served with status 200 instead of the list fails its way; the list comes through the next
// way, is taken once, and the next download from the host starts with that way.
func TestRemoteRuleSetDownloaderPage(t *testing.T) {
	list := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, downloaderList)
	}))
	defer list.Close()
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html><body>blocked by the provider</body></html>")
	}))
	defer page.Close()
	downloader := testRuleSetDownloader([]string{"isp", "works"}, map[string]adapter.HTTPTransport{
		"isp":   wayTo(page.Listener.Addr().String()),
		"works": testWay{&http.Transport{}},
	})
	set := rule.NewRemoteRuleSetForTest(list.URL, downloader)
	var updated int
	set.RegisterCallback(func(adapter.RuleSet) { updated++ })
	require.NoError(t, set.FetchForTest(context.Background(), false))
	require.Equal(t, 1, set.RulesForTest())
	require.Equal(t, 1, updated)
	parsed, _ := url.Parse(list.URL)
	ways, _ := downloader.Ways(parsed.Hostname())
	require.Equal(t, []string{"works", "isp"}, ways)
}

// At the start a way that never answers costs one wait of the plan, not the stall timeout nor the
// start deadline: the next way is started beside it.
func TestRemoteRuleSetDownloaderSilentAtStart(t *testing.T) {
	list := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, downloaderList)
	}))
	defer list.Close()
	silent := testWay{&http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}}
	downloader := testRuleSetDownloader([]string{"silent", "works"}, map[string]adapter.HTTPTransport{
		"silent": silent,
		"works":  testWay{&http.Transport{}},
	})
	set := rule.NewRemoteRuleSetForTest(list.URL, downloader)
	started := time.Now()
	require.NoError(t, set.FetchForTest(context.Background(), true))
	require.Equal(t, 1, set.RulesForTest())
	require.Less(t, time.Since(started), 2*time.Second)
}

// A box whose list client goes first through a SOCKS server that takes the connection and never
// answers (a local helper that hangs), then directly: the box starts with the list loaded after
// one wait of the downloader's plan, and the silent way never reaches the server of the list.
func TestRemoteRuleSetDownloaderInBox(t *testing.T) {
	var requests atomic.Int32
	list := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		io.WriteString(w, downloaderList)
	}))
	defer list.Close()
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer silent.Close()
	go func() {
		var held []net.Conn
		defer func() {
			for _, conn := range held {
				conn.Close()
			}
		}()
		for {
			conn, err := silent.Accept()
			if err != nil {
				return
			}
			held = append(held, conn)
		}
	}()
	port := silent.Addr().(*net.TCPAddr).Port
	config := `{
  "log": {"level": "debug"},
  "http_clients": [{"tag": "lists", "outbounds": ["helper", "direct"]}],
  "route": {
    "rule_set": [{"type": "remote", "tag": "list", "format": "source", "url": "` + list.URL + `", "update_interval": "1h", "http_client": "lists"}],
    "rules": [{"rule_set": ["list"], "outbound": "direct"}],
    "final": "direct"
  },
  "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "socks", "tag": "helper", "server": "127.0.0.1", "server_port": ` + strconv.Itoa(port) + `}]
}`
	logs := &memLog{}
	started := time.Now()
	instance := startBox(t, config, logs)
	took := time.Since(started)
	ruleSet, loaded := instance.Router().RuleSet("list")
	require.True(t, loaded)
	require.Equal(t, 1, logs.count("updated rule-set list"), logs.dump())
	require.False(t, ruleSet.Metadata().ContainsIPCIDRRule)
	require.EqualValues(t, 1, requests.Load())
	// one wait of the plan (4 s), not the stall (30 s) nor the start deadline (30 s)
	require.Less(t, took, 15*time.Second, logs.dump())
	require.Equal(t, 1, logs.count("through helper"), logs.dump())
}

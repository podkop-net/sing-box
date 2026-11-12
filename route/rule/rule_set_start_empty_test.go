package rule_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// A remote rule-set whose first download is slower than the start deadline starts empty
// (podkop-engine). The DNS router decides its rule mode from the sets' metadata right after
// the sets start, and an empty set would make it fix the non-legacy mode; the content that
// arrives later, with ip_cidr entries, would then be rejected by its validator for ever,
// and re-downloaded every few seconds. Until its content is known the set reports it as
// mixed, the one answer every later content is compatible with.

const mixedList = `{"version":3,"rules":[{"domain_suffix":["example.com"]},{"ip_cidr":["10.0.0.0/8"]}]}`

type memLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *memLog) WriteMessage(level log.Level, message string) {
	l.mu.Lock()
	l.lines = append(l.lines, message)
	l.mu.Unlock()
}

func (l *memLog) count(sub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, line := range l.lines {
		if strings.Contains(line, sub) {
			n++
		}
	}
	return n
}

func (l *memLog) dump() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// slowFirstListServer serves the list; the first request streams it over about a second,
// slow but steady, every later one answers at once.
func slowFirstListServer(t *testing.T, content string) (*httptest.Server, *atomic.Int32) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if requests.Add(1) == 1 {
			flusher := w.(http.Flusher)
			step := (len(content) + 9) / 10
			for i := 0; i < len(content); i += step {
				if _, err := w.Write([]byte(content[i:min(i+step, len(content))])); err != nil {
					return
				}
				flusher.Flush()
				time.Sleep(100 * time.Millisecond)
			}
			return
		}
		w.Write([]byte(content))
	}))
	t.Cleanup(server.Close)
	return server, &requests
}

func startEmptyConfig(url string, dnsRules string) string {
	return `{
  "log": {"level": "debug"},
  "dns": {
    "servers": [{"type": "udp", "tag": "dns-x", "server": "127.0.0.1", "server_port": 1}],
    "rules": [` + dnsRules + `]
  },
  "route": {
    "rule_set": [{"type": "remote", "tag": "list", "format": "source", "url": "` + url + `", "update_interval": "1h"}],
    "rules": [{"rule_set": ["list"], "outbound": "direct"}],
    "final": "direct"
  },
  "outbounds": [{"type": "direct", "tag": "direct"}]
}`
}

func startBox(t *testing.T, cfg string, logs *memLog) *box.Box {
	t.Chdir(t.TempDir()) // whatever the box writes (its cache file) stays out of the package
	ctx := include.Context(service.ContextWith[deprecated.Manager](context.Background(), deprecated.NewStderrManager(log.StdLogger())))
	var options option.Options
	require.NoError(t, options.UnmarshalJSONContext(ctx, []byte(cfg)))
	instance, err := box.New(box.Options{Context: ctx, Options: options, PlatformLogWriter: logs})
	require.NoError(t, err)
	require.NoError(t, instance.Start(), "the box must start, the set empty")
	t.Cleanup(func() { instance.Close() })
	return instance
}

func TestRuleSetStartedEmptyLoadsLater(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		dnsRules string
	}{
		// a DNS rule without any legacy-disabling field: the mode is decided by the sets
		{"plain DNS rule", `{"rule_set": ["list"], "action": "route", "server": "dns-x"}`},
		// podkop's generated config: a query_type rule first pins the non-legacy mode
		{"podkop's rules", `{"action": "reject", "query_type": "HTTPS"}, {"rule_set": ["list"], "action": "route", "server": "dns-x"}`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			defer rule.SwapTimeoutsForTest(10*time.Second, 300*time.Millisecond)()
			server, requests := slowFirstListServer(t, mixedList)
			logs := &memLog{}
			instance := startBox(t, startEmptyConfig(server.URL, testCase.dnsRules), logs)
			require.Equal(t, 1, logs.count("starting empty and retrying"), logs.dump())

			require.Eventually(t, func() bool { return logs.count("updated rule-set list") > 0 }, 10*time.Second, 100*time.Millisecond, "the list did not load afterwards:\n%s", logs.dump())
			ruleSet, loaded := instance.Router().RuleSet("list")
			require.True(t, loaded)
			require.True(t, ruleSet.Metadata().ContainsIPCIDRRule)
			require.Equal(t, 0, logs.count("Legacy Address Filter Fields"), logs.dump())
			require.Equal(t, int32(2), requests.Load(), "the start fetch and one load")
		})
	}
}

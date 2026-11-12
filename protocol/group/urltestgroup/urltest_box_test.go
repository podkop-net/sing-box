package urltestgroup_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// newGroupBox creates an instance from a configuration, as sing-box check does.
func newGroupBox(t *testing.T, content string) (*box.Box, error) {
	t.Helper()
	ctx := include.Context(service.ContextWith(context.Background(), deprecated.NewStderrManager(log.StdLogger())))
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(content))
	require.NoError(t, err)
	return box.New(box.Options{Context: ctx, Options: options})
}

// A group that names an outbound or a fallback the configuration does not have is refused when
// the box is created (sing-box 1.14.5 orders the outbounds by their dependencies then), as
// upstream's group is: sing-box check reports it, not the start. A fallback listed after the
// group is no missing one.
func TestBoxRefusesAMissingMember(t *testing.T) {
	for _, members := range []string{
		`"outbounds": ["a", "missing"]`,
		`"outbounds": ["a"], "fallbacks": ["missing"]`,
		`"outbounds": [], "fallbacks": ["missing", "a"]`,
	} {
		_, err := newGroupBox(t, `{
			"log": {"disabled": true},
			"outbounds": [
				{"type": "urltest", "tag": "g", `+members+`},
				{"type": "direct", "tag": "a"}
			]
		}`)
		require.ErrorContains(t, err, "dependency[missing] not found for outbound[g]", members)
	}
	instance, err := newGroupBox(t, `{
		"log": {"disabled": true},
		"outbounds": [
			{"type": "urltest", "tag": "g", "outbounds": ["a"], "fallbacks": ["f"]},
			{"type": "direct", "tag": "a"},
			{"type": "direct", "tag": "f"}
		]
	}`)
	require.NoError(t, err)
	require.NoError(t, instance.Close())
}

// A box whose group has a dead outbound and a fallback listed after it starts, and the group falls
// back to it: the fallback is a dependency of the group, started before it, and what the group then
// references.
func TestBoxStartsWithAFallbackAfterTheGroup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	deadPort := closed.Addr().(*net.TCPAddr).Port
	require.NoError(t, closed.Close())
	instance, err := newGroupBox(t, fmt.Sprintf(`{
		"log": {"disabled": true},
		"outbounds": [
			{"type": "urltest", "tag": "g", "outbounds": ["dead"], "fallbacks": ["f"], "url": %q, "download_url": ""},
			{"type": "socks", "tag": "dead", "server": "127.0.0.1", "server_port": %d},
			{"type": "direct", "tag": "f"}
		],
		"route": {"final": "g"}
	}`, server.URL, deadPort))
	require.NoError(t, err)
	t.Cleanup(func() { instance.Close() })
	require.NoError(t, instance.Start())
	outbound, loaded := instance.Outbound().Outbound("g")
	require.True(t, loaded)
	group := outbound.(adapter.OutboundGroup)
	require.Eventually(t, func() bool {
		return group.Selected(N.NetworkTCP).Tag() == "f"
	}, 10*time.Second, 20*time.Millisecond)
	references, dnsServers := outbound.(adapter.Referrer).References()
	require.Equal(t, []string{"f"}, references)
	require.Empty(t, dnsServers)
}

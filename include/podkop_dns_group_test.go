//go:build podkop_slim

package include

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// The DNS servers as podkop-exp writes a list of them (podkop-engine): a group of the
// servers and the provider, under the tag every rule points to.
func TestPodkopDNSGroup(t *testing.T) {
	err := newBox(`{"dns": {"servers": [
		{"type": "udp", "tag": "dns-server-1", "server": "77.88.8.8", "server_port": 53},
		{"type": "udp", "tag": "bootstrap-dns-server", "server": "77.88.8.8"},
		{"type": "https", "tag": "dns-server-2", "server": "dns.example", "server_port": 443, "path": "/dns-query", "domain_resolver": "bootstrap-dns-server"},
		{"type": "provider", "tag": "dns-server-3"},
		{"type": "group", "tag": "dns-server", "servers": ["dns-server-1", "dns-server-2", "dns-server-3"], "strategy": "order"}
	], "final": "dns-server"}}`)
	require.NoError(t, err)
	require.NoError(t, newBox(`{"dns": {"servers": [{"type": "provider", "tag": "dns-server"}], "final": "dns-server"}}`))

	// what is wrong is refused by the configuration check
	for _, testCase := range []struct {
		servers string
		message string
	}{
		{`{"type": "udp", "tag": "a", "server": "1.1.1.1"}, {"type": "group", "tag": "dns-server", "servers": ["a", "missing"]}`,
			"server missing of group dns-server not found"},
		{`{"type": "udp", "tag": "a", "server": "1.1.1.1"}, {"type": "fakeip", "tag": "f", "inet4_range": "198.18.0.0/15"}, {"type": "group", "tag": "dns-server", "servers": ["a", "f"]}`,
			"server f of group dns-server is of the type fakeip"},
		{`{"type": "udp", "tag": "a", "server": "1.1.1.1"}, {"type": "group", "tag": "inner", "servers": ["a"]}, {"type": "group", "tag": "dns-server", "servers": ["a", "inner"]}`,
			"server inner of group dns-server is a group"},
		{`{"type": "udp", "tag": "a", "server": "1.1.1.1"}, {"type": "group", "tag": "dns-server", "servers": ["a"], "strategy": "random"}`,
			"unknown strategy of group dns-server: random"},
		{`{"type": "group", "tag": "dns-server", "servers": []}`, "missing servers of group dns-server"},
		{`{"type": "udp", "tag": "a", "server": "1.1.1.1"}, {"type": "group", "tag": "dns-server", "servers": ["a", "a"]}`,
			"duplicate server a in group dns-server"},
	} {
		err := newBox(`{"dns": {"servers": [` + testCase.servers + `], "final": "dns-server"}}`)
		require.ErrorContains(t, err, testCase.message, testCase.servers)
	}
}

// testDNSResolver answers A queries with 1.2.3.4.
func testDNSResolver(t *testing.T) int {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query mDNS.Msg
			if query.Unpack(buffer[:n]) != nil {
				continue
			}
			response := new(mDNS.Msg)
			response.SetReply(&query)
			response.Answer = []mDNS.RR{&mDNS.A{Hdr: mDNS.RR_Header{Name: query.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 300}, A: net.IPv4(1, 2, 3, 4)}}
			packed, _ := response.Pack()
			conn.WriteTo(packed, addr)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// A started box answers through the group: the first member refuses (nothing listens on its
// port), the second answers; a program that runs the box reads the state of the group through
// the DNS transport manager of the box.
func TestPodkopDNSGroupStarted(t *testing.T) {
	closed, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	closedPort := closed.LocalAddr().(*net.UDPAddr).Port
	closed.Close()
	goodPort := testDNSResolver(t)

	ctx := Context(service.ContextWith(context.Background(), deprecated.NewStderrManager(log.StdLogger())))
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"log": {"level": "warn"},
		"dns": {"servers": [
			{"type": "udp", "tag": "dns-server-1", "server": "127.0.0.1", "server_port": `+strconv.Itoa(closedPort)+`},
			{"type": "udp", "tag": "dns-server-2", "server": "127.0.0.1", "server_port": `+strconv.Itoa(goodPort)+`},
			{"type": "group", "tag": "dns-server", "servers": ["dns-server-1", "dns-server-2"]}
		], "final": "dns-server"}
	}`))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	defer instance.Close()

	router := service.FromContext[adapter.DNSRouter](ctx)
	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	response, err := router.Exchange(queryCtx, message, adapter.DNSQueryOptions{})
	require.NoError(t, err)
	require.Len(t, response.Answer, 1)
	require.Equal(t, "1.2.3.4", response.Answer[0].(*mDNS.A).A.String())

	transport, loaded := service.FromContext[adapter.DNSTransportManager](ctx).Transport("dns-server")
	require.True(t, loaded)
	group, isGroup := transport.(adapter.DNSGroupTransport)
	require.True(t, isGroup)
	state := group.GroupState()
	require.Equal(t, "order", state.Strategy)
	require.Len(t, state.Members, 2)
	require.Equal(t, "udp", state.Members[0].Type)
	require.Equal(t, uint64(1), state.Members[0].Failures)
	require.Equal(t, uint64(1), state.Members[1].Answers)
	require.NotZero(t, state.Members[1].SmoothedTime)
}

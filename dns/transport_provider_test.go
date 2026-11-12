package dns

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func providerTestDump(t *testing.T) []netifdInterface {
	t.Helper()
	var dump struct {
		Interface []netifdInterface `json:"interface"`
	}
	require.NoError(t, json.Unmarshal([]byte(testUbusDump), &dump))
	return dump.Interface
}

// providerTestBox is the context of a box with the provider set given and a network manager
// (nil: sing-box binds no socket).
func providerTestBox(providers *providerSet, network adapter.NetworkManager) context.Context {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	if network != nil {
		service.MustRegister[adapter.NetworkManager](ctx, network)
	}
	service.MustRegister[*providerSet](ctx, providers)
	return ctx
}

func newProviderTest(t *testing.T, ctx context.Context) *ProviderTransport {
	t.Helper()
	logger, _ := groupTestLogger(t)
	transport, err := NewProviderTransport(ctx, logger, "isp", option.ProviderDNSServerOptions{})
	require.NoError(t, err)
	return transport.(*ProviderTransport)
}

func providerTestServers(servers []adapter.DNSProviderServer) string {
	var names []string
	for _, server := range servers {
		name := server.Address.String()
		if server.Device != "" {
			name += " on " + server.Device
		}
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}

// The servers it asks, from netifd: those of every uplink, each bound to its device, or
// those of the device sing-box binds its sockets to.
func TestProviderTransportServers(t *testing.T) {
	t.Parallel()
	dump := providerTestDump(t)
	read := func(ctx context.Context) ([]netifdInterface, error) { return dump, nil }

	ctx := providerTestBox(&providerSet{read: read}, nil)
	transport := newProviderTest(t, ctx)
	require.Equal(t, C.DNSTypeProvider, transport.Type())
	require.Nil(t, fallbackFor(transport), "the provider has a fallback of its own")
	want := "10.99.0.53:53 on wan0, 10.99.0.54:53 on wan0, 100.64.5.1:53 on wwan0, [fe80::1%wan0]:53 on wan0, [2a00::53]:53 on wan0"
	require.Equal(t, want, providerTestServers(transport.ProviderServers()))
	require.Equal(t, want, providerTestServers(ProviderServers(ctx)))

	// boundNetwork has no more of a network manager than the device: no dialer is made of it
	bound := providerTestBox(&providerSet{read: read}, boundNetwork{device: "wwan0"})
	require.Equal(t, "100.64.5.1:53", providerTestServers(ProviderServers(bound)))
}

// It asks the provider's servers as the fallback does: all at once, REFUSED skipped, the one
// that answered alone next time; the answer is as the server gave it.
func TestProviderTransportExchange(t *testing.T) {
	t.Parallel()
	silent, refused, good := testResolver(t, -1), testResolver(t, mDNS.RcodeRefused), testResolver(t, mDNS.RcodeSuccess)
	providers := &providerSet{servers: []M.Socksaddr{silent, refused, good}, readAt: time.Now()}
	transport := newProviderTest(t, providerTestBox(providers, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	response, err := transport.Exchange(ctx, freshTestQuery())
	require.NoError(t, err)
	require.Equal(t, "1.2.3.4", groupTestWho(response, err))
	require.Equal(t, uint32(300), response.Answer[0].Header().Ttl, "the TTL of a provider server is its own")
	best, loaded := providers.pick(providers.servers)
	require.True(t, loaded)
	require.Equal(t, good, best)

	none := newProviderTest(t, providerTestBox(&providerSet{servers: []M.Socksaddr{silent, refused}, readAt: time.Now()}, nil))
	ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err = none.Exchange(ctx, freshTestQuery())
	require.Error(t, err)
}

// With no server known it fails at once (a group moves on), and reads the list again
// providerRetryAfter later, not at every query; a network reset makes it read the list at
// the next query.
func TestProviderTransportNoServers(t *testing.T) {
	t.Parallel()
	var reads atomic.Int32
	providers := &providerSet{read: func(ctx context.Context) ([]netifdInterface, error) {
		reads.Add(1)
		return nil, nil // no uplink has DNS servers yet
	}}
	transport := newProviderTest(t, providerTestBox(providers, nil))
	exchange := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		startAt := time.Now()
		_, err := transport.Exchange(ctx, freshTestQuery())
		if time.Since(startAt) > 500*time.Millisecond {
			t.Errorf("failed after %v", time.Since(startAt))
		}
		return err
	}
	require.ErrorIs(t, exchange(), errNoProviders)
	require.ErrorIs(t, exchange(), errNoProviders)
	require.Equal(t, int32(1), reads.Load(), "the list was read at every query")
	providers.access.Lock()
	providers.readAt = time.Now().Add(-providerRetryAfter)
	providers.access.Unlock()
	require.ErrorIs(t, exchange(), errNoProviders)
	require.Equal(t, int32(2), reads.Load(), "the list was not read again")
	transport.Reset()
	require.ErrorIs(t, exchange(), errNoProviders)
	require.Equal(t, int32(3), reads.Load(), "the list was not read again after a network reset")
}

// A query that finds no server while another one reads the list waits for that read.
func TestProviderListWait(t *testing.T) {
	t.Parallel()
	dump := providerTestDump(t)
	reading, release := make(chan struct{}), make(chan struct{})
	providers := &providerSet{read: func(ctx context.Context) ([]netifdInterface, error) {
		close(reading)
		<-release
		return dump, nil
	}}
	go providers.list(context.Background(), nil)
	<-reading
	got := make(chan []M.Socksaddr)
	go func() {
		got <- providers.listWait(context.Background(), context.Background(), nil)
	}()
	select {
	case servers := <-got:
		t.Fatalf("returned %v while the list was read", servers)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	require.Equal(t, "10.99.0.53, 10.99.0.54, 100.64.5.1, fe80::1%wan0, 2a00::53", joinServers(<-got))

	// the caller gives up while it waits
	stuck := &providerSet{read: func(ctx context.Context) ([]netifdInterface, error) {
		<-ctx.Done() // never: the read has its own context
		return nil, E.New("unreachable")
	}}
	stuck.access.Lock()
	stuck.reading, stuck.readDone = true, make(chan struct{})
	stuck.access.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	require.Nil(t, stuck.listWait(ctx, context.Background(), nil))
}

// A server of an uplink is asked through the dialer bound to the device of that uplink.
func TestProviderTransportThroughUplink(t *testing.T) {
	t.Parallel()
	ofUplink, ofSystem := testResolver(t, mDNS.RcodeSuccess), testResolver(t, -1)
	own, bound := &recordingDialer{Dialer: N.SystemDialer}, &recordingDialer{Dialer: N.SystemDialer}
	providers := &providerSet{
		servers: []M.Socksaddr{ofUplink, ofSystem},
		devices: map[M.Socksaddr]string{ofUplink: "wan9"},
		readAt:  time.Now(),
	}
	transport := newProviderTest(t, providerTestBox(providers, nil))
	transport.asker.dialer = own
	transport.asker.bound = map[string]N.Dialer{"wan9": bound}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	response, err := transport.Exchange(ctx, freshTestQuery())
	require.Equal(t, "1.2.3.4", groupTestWho(response, err))
	require.Equal(t, []string{ofUplink.String()}, bound.told())
	require.Equal(t, []string{ofSystem.String()}, own.told())
}

// A provider server as the last member of a group: it answers when the others fail, with
// its own TTL, and there is no safety net besides it.
func TestProviderTransportInGroup(t *testing.T) {
	t.Parallel()
	ctx := providerTestBox(&providerSet{servers: []M.Socksaddr{testResolver(t, mDNS.RcodeSuccess)}, readAt: time.Now()}, nil)
	provider := newProviderTest(t, ctx)
	dead := newGroupTestMember("dead", fallbackTestFails)
	group, _ := newGroupTest(t, ctx, C.DNSGroupStrategyOrder, true, dead, provider)
	require.False(t, group.GroupState().SafetyNet)
	queryCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	response, err := group.Exchange(queryCtx, freshTestQuery())
	require.Equal(t, "1.2.3.4", groupTestWho(response, err))
	require.Equal(t, uint32(300), response.Answer[0].Header().Ttl)
	require.Equal(t, C.DNSTypeProvider, group.testMember("isp").Type)
	require.Equal(t, uint64(1), group.testMember("isp").Answers)
}

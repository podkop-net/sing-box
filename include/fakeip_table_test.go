package include

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func newFakeIPBox(t *testing.T, server string, cachePath string) (context.Context, *box.Box, error) {
	t.Helper()
	ctx := Context(service.ContextWith(context.Background(), deprecated.NewStderrManager(log.StdLogger())))
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
		"log": {"level": "error"},
		"dns": {"servers": [{"type": "udp", "tag": "udp", "server": "127.0.0.1"}, `+server+`]},
		"experimental": {"cache_file": {"enabled": true, "path": "`+cachePath+`", "store_fakeip": true}}
	}`))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	return ctx, instance, err
}

// The FakeIP server of a box is upstream's with the store of this fork: the registry has
// RegisterTableTransport after upstream's RegisterTransport. Upstream's checks of the
// options stay.
func TestFakeIPServerHasTableStore(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "cache.db")
	ctx, instance, err := newFakeIPBox(t, `{"type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/15"}`, cachePath)
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	transport := service.FromContext[adapter.DNSTransportManager](ctx).FakeIP()
	require.NotNil(t, transport)
	store, isTable := transport.Store().(*fakeip.TableStore)
	require.True(t, isTable, "%T", transport.Store())

	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	response, err := transport.Exchange(ctx, message)
	require.NoError(t, err)
	require.Len(t, response.Answer, 1)
	address, found := store.Peek("example.com", false)
	require.True(t, found)
	require.Equal(t, response.Answer[0].(*mDNS.A).A.String(), address.String())
	require.NoError(t, instance.Close())

	// the next start reads the table the stop saved
	ctx, instance, err = newFakeIPBox(t, `{"type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/15"}`, cachePath)
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	domain, loaded := service.FromContext[adapter.DNSTransportManager](ctx).FakeIP().Store().Lookup(address)
	require.True(t, loaded)
	require.Equal(t, "example.com", domain)
	require.NoError(t, instance.Close())

	_, _, err = newFakeIPBox(t, `{"type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/31"}`, cachePath)
	require.ErrorContains(t, err, "inet4_range must have at least 2 host bits")
}

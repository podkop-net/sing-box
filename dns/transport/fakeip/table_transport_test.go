package fakeip

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func prefixOption(text string) *badoption.Prefix {
	prefix := badoption.Prefix(netip.MustParsePrefix(text))
	return &prefix
}

// The server is upstream's, with the store of this fork; upstream's checks of the options
// stay.
func TestTableTransport(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	logger := log.NewNOPFactory().NewLogger("dns")
	transport, err := NewTableTransport(ctx, logger, "fakeip", option.FakeIPDNSServerOptions{
		Inet4Range: prefixOption("198.18.0.0/15"),
		Inet6Range: prefixOption("fc00::/18"),
	})
	require.NoError(t, err)
	require.Equal(t, C.DNSTypeFakeIP, transport.Type())
	require.Equal(t, "fakeip", transport.Tag())
	server, isFakeIP := transport.(adapter.FakeIPTransport)
	require.True(t, isFakeIP)
	store, isTable := server.Store().(*TableStore)
	require.True(t, isTable, "%T", server.Store())
	require.Equal(t, netip.MustParsePrefix("198.18.0.0/15"), store.inet4Range)
	require.Equal(t, netip.MustParsePrefix("fc00::/18"), store.inet6Range)
	scope := adapter.NewScope(ctx, logger)
	require.NoError(t, transport.Start(adapter.StartStateStart, scope))

	message := new(mDNS.Msg)
	message.SetQuestion("Example.COM.", mDNS.TypeAAAA)
	response, err := transport.Exchange(ctx, message)
	require.NoError(t, err)
	require.Len(t, response.Answer, 1)
	address, found := store.Peek("example.com", true)
	require.True(t, found)
	require.Equal(t, address.String(), response.Answer[0].(*mDNS.AAAA).AAAA.String())
	domain, loaded := store.Lookup(address)
	require.True(t, loaded)
	require.Equal(t, "example.com", domain)
	require.NoError(t, scope.Close())

	for _, testCase := range []struct {
		options option.FakeIPDNSServerOptions
		message string
	}{
		{option.FakeIPDNSServerOptions{}, "at least one of inet4_range or inet6_range must be set"},
		{option.FakeIPDNSServerOptions{Inet4Range: prefixOption("198.18.0.0/31")}, "inet4_range must have at least 2 host bits"},
		{option.FakeIPDNSServerOptions{Inet6Range: prefixOption("fc00::/127")}, "inet6_range must have at least 2 host bits"},
	} {
		_, err = NewTableTransport(ctx, logger, "fakeip", testCase.options)
		require.ErrorContains(t, err, testCase.message)
	}
}

// RegisterTableTransport takes the place of upstream's server in a registry that has it.
func TestRegisterTableTransport(t *testing.T) {
	t.Parallel()
	registry := dns.NewTransportRegistry()
	RegisterTransport(registry)
	RegisterTableTransport(registry)
	options, loaded := registry.CreateOptions(C.DNSTypeFakeIP)
	require.True(t, loaded)
	options.(*option.FakeIPDNSServerOptions).Inet4Range = prefixOption("198.18.0.0/15")
	transport, err := registry.CreateDNSTransport(context.Background(), log.NewNOPFactory().NewLogger("dns"), "fakeip", C.DNSTypeFakeIP, options)
	require.NoError(t, err)
	_, isTable := transport.(adapter.FakeIPTransport).Store().(*TableStore)
	require.True(t, isTable)
}

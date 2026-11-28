package fakeip

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// RegisterTableTransport registers the FakeIP server of NewTableTransport. It is called
// after RegisterTransport and takes the place of upstream's server: a registry keeps the
// last constructor registered for a type.
func RegisterTableTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.FakeIPDNSServerOptions](registry, C.DNSTypeFakeIP, NewTableTransport)
}

// NewTableTransport is upstream's FakeIP server with a TableStore in place of upstream's
// store. The server is upstream's NewTransport as it is: its checks of the options and its
// answers. The store NewTransport builds only checks the ranges (it reads nothing and
// starts nothing before Start) and is dropped unstarted.
func NewTableTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.FakeIPDNSServerOptions) (adapter.DNSTransport, error) {
	transport, err := NewTransport(ctx, logger, tag, options)
	if err != nil {
		return nil, err
	}
	server, isServer := transport.(*Transport)
	if !isServer {
		return nil, E.New("fakeip: NewTransport returned ", fmt.Sprintf("%T", transport), ", the store in memory has no place in it")
	}
	// the ranges as NewTransport reads them
	server.store = NewTableStore(ctx, logger, options.Inet4Range.Build(netip.Prefix{}), options.Inet6Range.Build(netip.Prefix{}))
	return server, nil
}

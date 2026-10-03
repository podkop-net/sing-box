//go:build podkop_slim

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

// The tag podkop_slim builds what podkop uses (podkop-engine): the types left out are
// registered as stubs, so that a configuration naming one fails with this message instead
// of an unknown type.

const notIncludedSlim = " is not included in this build (podkop_slim)"

func registerNonPodkopInbounds(registry *inbound.Registry) {
	stubInbound(registry, C.TypeTun)
	stubInbound(registry, C.TypeRedirect)
	stubInbound(registry, C.TypeSOCKS)
	stubInbound(registry, C.TypeHTTP)
	stubInbound(registry, C.TypeShadowsocks)
	stubInbound(registry, C.TypeVMess)
	stubInbound(registry, C.TypeTrojan)
	stubInbound(registry, C.TypeNaive)
	stubInbound(registry, C.TypeShadowTLS)
	stubInbound(registry, C.TypeVLESS)
	stubInbound(registry, C.TypeAnyTLS)
	stubInbound(registry, C.TypeHysteria)
	stubInbound(registry, C.TypeTUIC)
	stubInbound(registry, C.TypeHysteria2)
}

func registerNonPodkopOutbounds(registry *outbound.Registry) {
	stubOutbound(registry, C.TypeBlock, notIncludedSlim+", use the rule action reject")
}

func registerNonPodkopDNSTransports(registry *dns.TransportRegistry) {
	stubDNSTransport(registry, C.DNSTypeQUIC)
	stubDNSTransport(registry, C.DNSTypeHTTP3)
}

func registerNonPodkopServices(registry *service.Registry) {
	stubService(registry, C.TypeSSMAPI)
	stubService(registry, C.TypeOOMKiller)
}

// stubOptions takes the options of a type left out whatever they are: its own options type,
// with the code that parses and checks it, stays out of the binary too.
type stubOptions struct{}

func (*stubOptions) UnmarshalJSON([]byte) error {
	return nil
}

func stubInbound(registry *inbound.Registry, inboundType string) {
	inbound.Register[stubOptions](registry, inboundType, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options stubOptions) (adapter.Inbound, error) {
		return nil, E.New(inboundType, " inbound", notIncludedSlim)
	})
}

func stubOutbound(registry *outbound.Registry, outboundType string, reason string) {
	outbound.Register[stubOptions](registry, outboundType, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options stubOptions) (adapter.Outbound, error) {
		return nil, E.New(outboundType, " outbound", reason)
	})
}

func stubDNSTransport(registry *dns.TransportRegistry, transportType string) {
	dns.RegisterTransport[stubOptions](registry, transportType, func(ctx context.Context, logger log.ContextLogger, tag string, options stubOptions) (adapter.DNSTransport, error) {
		return nil, E.New(transportType, " DNS server", notIncludedSlim)
	})
}

func stubService(registry *service.Registry, serviceType string) {
	service.Register[stubOptions](registry, serviceType, func(ctx context.Context, logger log.ContextLogger, tag string, options stubOptions) (adapter.Service, error) {
		return nil, E.New(serviceType, " service", notIncludedSlim)
	})
}

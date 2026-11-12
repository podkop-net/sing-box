package dns

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	mDNS "github.com/miekg/dns"
)

// The DNS server of the type provider (podkop-engine) asks the DNS servers of the internet
// provider: those netifd knows, the same list and the same way as the provider DNS fallback
// (client_fallback_provider.go). They are the servers of the output device of sing-box, or
// of every uplink when sing-box binds no socket, each asked through its uplink from a fresh
// socket: the one that answered last alone, all at once when it does not answer, a REFUSED
// skipped. It works whether the fallback is enabled or not, and has no fallback of its own:
// it is the provider. With no server known it fails at once, so that a group moves on to
// its next member, and the list is read again 30 s later (DHCP may hand the servers out
// after sing-box started). A network reset forgets the list.

func RegisterProviderTransport(registry *TransportRegistry) {
	RegisterTransport[option.ProviderDNSServerOptions](registry, C.DNSTypeProvider, NewProviderTransport)
}

var _ adapter.DNSProviderTransport = (*ProviderTransport)(nil)

type ProviderTransport struct {
	TransportAdapter
	ctx    context.Context
	logger logger.ContextLogger
	asker  *fallbackServer
}

func NewProviderTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.ProviderDNSServerOptions) (adapter.DNSTransport, error) {
	asker, err := newProviderAsker(ctx)
	if err != nil {
		return nil, err
	}
	return &ProviderTransport{
		TransportAdapter: NewTransportAdapter(C.DNSTypeProvider, tag, nil),
		ctx:              ctx,
		logger:           logger,
		asker:            asker,
	}, nil
}

// newProviderAsker is the part of a fallback server that asks the provider's servers of the
// box of ctx, for a server that is not itself a remote one (the provider DNS server, the
// safety net of a group): a plain socket of the box, as the fallback of a server qualifies
// with one only, bound to the device of an uplink for a server of an uplink (dialerFor).
func newProviderAsker(ctx context.Context) (*fallbackServer, error) {
	var options option.RemoteDNSServerOptions
	dialer, err := NewRemoteDialer(ctx, options)
	if err != nil {
		return nil, err
	}
	return &fallbackServer{options: options, eligible: true, dialer: dialer, ctx: ctx, providers: providersFrom(ctx)}, nil
}

func (t *ProviderTransport) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return nil
}

// Reset forgets the list: the uplinks and their servers may have changed. The DNS router
// does it for the list of the box on a network reset anyway.
func (t *ProviderTransport) Reset() {
	t.asker.providers.forget()
}

func (t *ProviderTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	servers := t.asker.providers.listWait(ctx, t.ctx, t.logger)
	if len(servers) == 0 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		t.asker.providers.noneAnswered() // read the list again in providerRetryAfter
		return nil, errNoProviders
	}
	return t.asker.askProviders(ctx, servers, message)
}

// ExchangeAsync must not keep the caller: the first query reads the list (an exec of ubus).
func (t *ProviderTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	go func() {
		callback(t.Exchange(ctx, message))
	}()
}

func (t *ProviderTransport) ProviderServers() []adapter.DNSProviderServer {
	t.asker.providers.list(t.ctx, t.logger)
	return t.asker.providers.snapshot()
}

// ProviderServers returns the provider's servers of the box of ctx as the provider DNS
// server, the fallback and the safety net of a group ask them now, for diagnostics of a
// program that runs the box in its process; ctx carries the services of the box. When the
// list is due to be read, it reads it first, which runs ubus.
func ProviderServers(ctx context.Context) []adapter.DNSProviderServer {
	providers := providersFrom(ctx)
	providers.list(ctx, nil)
	return providers.snapshot()
}

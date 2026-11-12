package transport

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"

	mDNS "github.com/miekg/dns"
)

// Plain DNS over UDP sends every query from its own socket (see dns.ExchangeFresh) when
// the query leaves through a socket of this process: no detour, or a detour to a direct
// outbound, whatever interface or mark it binds to. Through a proxy the shared session
// stays: a new UDP session of VLESS, VMess, Trojan or SOCKS is a new TCP (and TLS)
// connection to the proxy server.
type freshSocket struct {
	ctx     context.Context
	options option.RemoteDNSServerOptions
	once    sync.Once
	enabled bool
}

// freshEnabled is decided at the first query: outbounds are created after DNS servers.
func (t *UDPTransport) freshEnabled() bool {
	if t.fresh == nil {
		return false
	}
	t.fresh.once.Do(func() { t.fresh.enabled = dns.DirectRoute(t.fresh.ctx, t.fresh.options) })
	return t.fresh.enabled
}

func (t *UDPTransport) exchangeQuery(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if !t.freshEnabled() {
		return t.multiplexer.Exchange(ctx, message)
	}
	return dns.ExchangeFresh(ctx, t.dialer, t.serverAddr, message)
}

func (t *UDPTransport) exchangeQueryAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	if !t.freshEnabled() {
		t.multiplexer.ExchangeAsync(ctx, message, callback)
		return
	}
	go func() {
		callback(dns.ExchangeFresh(ctx, t.dialer, t.serverAddr, message))
	}()
}

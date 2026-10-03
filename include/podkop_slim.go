//go:build !podkop_slim

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing-box/protocol/redirect"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/shadowtls"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing-box/service/ssmapi"
)

// What the tag podkop_slim leaves out (podkop_slim_stub.go): podkop only listens with
// tproxy, direct and mixed, writes the DNS servers udp, tls, https and fakeip, and
// configures no services.

func registerNonPodkopInbounds(registry *inbound.Registry) {
	tun.RegisterInbound(registry)
	redirect.RegisterRedirect(registry)
	socks.RegisterInbound(registry)
	http.RegisterInbound(registry)
	shadowsocks.RegisterInbound(registry)
	vmess.RegisterInbound(registry)
	trojan.RegisterInbound(registry)
	naive.RegisterInbound(registry)
	shadowtls.RegisterInbound(registry)
	vless.RegisterInbound(registry)
	anytls.RegisterInbound(registry)
	registerQUICInbounds(registry)
}

func registerNonPodkopOutbounds(registry *outbound.Registry) {
	block.RegisterOutbound(registry)
}

func registerNonPodkopDNSTransports(registry *dns.TransportRegistry) {
	registerQUICTransports(registry)
}

func registerNonPodkopServices(registry *service.Registry) {
	ssmapi.RegisterService(registry)
	registerOOMKillerService(registry)
}

//go:build !podkop_slim

package include

import (
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/block"
	"github.com/sagernet/sing-box/protocol/bridge"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing-box/protocol/redirect"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/shadowtls"
	"github.com/sagernet/sing-box/protocol/snell"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/tun"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing-box/service/api"
	originca "github.com/sagernet/sing-box/service/origin_ca"
	"github.com/sagernet/sing-box/service/ssmapi"
)

// What the tag podkop_slim leaves out (podkop_slim_stub.go): podkop only listens with
// tproxy, direct and mixed, writes the DNS servers udp, tls, https and fakeip, and
// configures no services and no certificate providers.

func registerNonPodkopInbounds(registry *inbound.Registry) {
	tun.RegisterInbound(registry)
	redirect.RegisterRedirect(registry)
	socks.RegisterInbound(registry)
	http.RegisterInbound(registry)
	shadowsocks.RegisterInbound(registry)
	snell.RegisterInbound(registry)
	vmess.RegisterInbound(registry)
	trojan.RegisterInbound(registry)
	naive.RegisterInbound(registry)
	shadowtls.RegisterInbound(registry)
	vless.RegisterInbound(registry)
	anytls.RegisterInbound(registry)
	registerQUICInbounds(registry)
}

func registerNonPodkopOutbounds(registry *outbound.Registry) {
	bridge.RegisterOutbound(registry)
	block.RegisterOutbound(registry)
}

func registerNonPodkopDNSTransports(registry *dns.TransportRegistry) {
	registerQUICTransports(registry)
}

func registerAPIService(registry *service.Registry) {
	api.RegisterService(registry)
}

func registerNonPodkopServices(registry *service.Registry) {
	ssmapi.RegisterService(registry)
	registerQUICServices(registry)
	registerOOMKillerService(registry)
}

func registerNonPodkopCertificateProviders(registry *certificate.Registry) {
	originca.RegisterCertificateProvider(registry)
}

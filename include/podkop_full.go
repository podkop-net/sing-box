//go:build !podkop_slim || podkop_full

package include

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/shadowtls"
	"github.com/sagernet/sing-box/protocol/ssh"
	"github.com/sagernet/sing-box/protocol/tor"
	"github.com/sagernet/sing-box/protocol/vmess"
)

// The outbounds podkop does not write itself, reachable only through a raw outbound
// configuration: podkop_slim leaves them out, podkop_full puts them back
// (podkop-engine-full). The naive outbound also needs with_naive_outbound.

func registerFullOutbounds(registry *outbound.Registry) {
	vmess.RegisterOutbound(registry)
	registerNaiveOutbound(registry)
	tor.RegisterOutbound(registry)
	ssh.RegisterOutbound(registry)
	shadowtls.RegisterOutbound(registry)
	anytls.RegisterOutbound(registry)
}

//go:build with_quic && (!podkop_slim || podkop_full)

package include

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/protocol/hysteria"
)

func registerHysteriaOutbound(registry *outbound.Registry) {
	hysteria.RegisterOutbound(registry)
}

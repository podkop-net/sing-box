//go:build with_quic && podkop_slim && !podkop_full

package include

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
)

func registerHysteriaOutbound(registry *outbound.Registry) {
	stubOutbound(registry, C.TypeHysteria, notIncludedFull)
}

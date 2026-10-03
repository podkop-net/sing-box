//go:build podkop_slim && !podkop_full

package include

import (
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
)

const notIncludedFull = notIncludedSlim + ", install podkop-engine-full or rebuild with -tags podkop_full"

func registerFullOutbounds(registry *outbound.Registry) {
	stubOutbound(registry, C.TypeHTTP, notIncludedFull)
	stubOutbound(registry, C.TypeVMess, notIncludedFull)
	stubOutbound(registry, C.TypeNaive, notIncludedFull)
	stubOutbound(registry, C.TypeTor, notIncludedFull)
	stubOutbound(registry, C.TypeSSH, notIncludedFull)
	stubOutbound(registry, C.TypeShadowTLS, notIncludedFull)
	stubOutbound(registry, C.TypeAnyTLS, notIncludedFull)
}

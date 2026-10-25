//go:build with_utls

package tls

import (
	"github.com/sagernet/sing/common"

	utls "github.com/metacubex/utls"
)

// dropMLKEM takes the X25519MLKEM768 group out of the supported groups and the key shares of
// a ClientHello whose handshake state is built: the ClientHello of the fingerprint as stock
// sing-box sends it under REALITY. The caller builds the state again.
func dropMLKEM(uConn *utls.UConn) {
	for _, extension := range uConn.Extensions {
		if curves, isCurves := extension.(*utls.SupportedCurvesExtension); isCurves {
			curves.Curves = common.Filter(curves.Curves, func(curveID utls.CurveID) bool {
				return curveID != utls.X25519MLKEM768
			})
		}
		if keyShares, isKeyShares := extension.(*utls.KeyShareExtension); isKeyShares {
			keyShares.KeyShares = common.Filter(keyShares.KeyShares, func(share utls.KeyShare) bool {
				return share.Group != utls.X25519MLKEM768
			})
		}
	}
}

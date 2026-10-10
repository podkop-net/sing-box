package encryption

import (
	"net"
	"reflect"
	"unsafe"

	"github.com/sagernet/sing-vmess/vless"
	N "github.com/sagernet/sing/common/network"
)

// The flow xtls-rprx-vision over this layer (podkop-engine).
//
// Vision reads what the security layer under it has taken from the wire and not handed
// over yet, and once the inner TLS 1.3 is seen it writes past that layer. sing-vmess
// finds the layer through a list of the connections it knows, crypto/tls and uTLS; Xray
// treats this layer the same way: CommonConn has the fields input and rawInput for that
// very reason, and the direct copy goes to the connection right under it (UnwrapRawConn
// of Xray). One more entry of the list gives sing-vmess the same view.
//
// CommonConn does not say what is under it (no Upstream), so a TLS connection under this
// layer is not found by the entries before this one, and is not written past: Xray does
// not do that either.

// The import makes the list of sing-vmess complete before this entry is added.
var _ = vless.FlowVision

//go:linkname visionRegistry github.com/sagernet/sing-vmess/vless.tlsRegistry
var visionRegistry []func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer uintptr)

func init() {
	visionRegistry = append(visionRegistry, func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer uintptr) {
		commonConn, loaded := N.CastReader[*CommonConn](conn)
		if !loaded {
			return
		}
		return true, commonConn.Conn, reflect.TypeOf(commonConn).Elem(), uintptr(unsafe.Pointer(commonConn))
	})
}

//go:build with_quic

package v2ray_test

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	_ "github.com/sagernet/sing-box/transport/v2rayquic"
)

func init() {
	clientTransportCases = append(clientTransportCases,
		clientTransportCase{name: "quic", options: option.V2RayTransportOptions{Type: C.V2RayTransportTypeQUIC}, alpn: []string{}},
		clientTransportCase{name: "xhttp, HTTP/3", options: option.V2RayTransportOptions{Type: C.V2RayTransportTypeXHTTP}, alpn: []string{"h3"}},
	)
}

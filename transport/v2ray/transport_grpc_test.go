//go:build with_grpc

package v2ray_test

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func init() {
	for i, c := range clientTransportCases {
		if c.options.Type == C.V2RayTransportTypeGRPC {
			// With this tag "grpc" is the client of grpc-go, which connects under
			// the context of the transport and waits for the server for as long
			// as that lives: with a dialer that only fails, its dial never
			// returns.
			clientTransportCases[i].skip = "the grpc-go client waits for its server"
		}
	}
	forceLite := option.V2RayTransportOptions{Type: C.V2RayTransportTypeGRPC, GRPCOptions: option.V2RayGRPCOptions{ForceLite: true}}
	clientTransportCases = append(clientTransportCases,
		clientTransportCase{name: "grpc, lite", options: forceLite},
		clientTransportCase{name: "grpc, lite, TLS", options: forceLite, alpn: []string{}},
	)
}

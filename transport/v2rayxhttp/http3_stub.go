//go:build !with_quic

package v2rayxhttp

import (
	"time"

	"github.com/sagernet/sing-box/common/tls"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func newHTTP3Connections(dialer N.Dialer, serverAddr M.Socksaddr, tlsConfig tls.Config, keepAlivePeriod time.Duration) (func() pooledConnection, error) {
	return nil, E.New("xhttp: HTTP/3 (tls.alpn [\"h3\"]) needs a build with QUIC")
}

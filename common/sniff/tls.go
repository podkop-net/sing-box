package sniff

import (
	"context"
	"crypto/tls"
	"errors"
	"io"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
)

// errClientHelloCaptured ends the server handshake as soon as the ClientHello is parsed.
// Returning (nil, nil) from GetConfigForClient would let it go on into the server's key
// exchange (X25519, plus ML-KEM for the post-quantum hellos current browsers send) and only
// then fail for want of a certificate: about 30 times the cost of the parse, all discarded.
var errClientHelloCaptured = errors.New("tls: client hello captured")

func TLSClientHello(ctx context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	var clientHello *tls.ClientHelloInfo
	err := tls.Server(bufio.NewReadOnlyConn(reader), &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			clientHello = argHello
			return nil, errClientHelloCaptured
		},
	}).HandshakeContext(ctx)
	if clientHello != nil {
		metadata.Protocol = C.ProtocolTLS
		metadata.Domain = clientHello.ServerName
		return nil
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return E.Cause1(ErrNeedMoreData, err)
	} else {
		return err
	}
}

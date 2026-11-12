package tls

import (
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

// QUICClientOptions are the TLS options of an outbound that runs over QUIC (hysteria,
// hysteria2, tuic) as it can use them: quic-go makes the ClientHello itself, so a uTLS
// fingerprint cannot be sent, and with one every connection failed ("unsupported usage
// for uTLS"). The fingerprint is dropped with a warning, as the decoder of share links
// drops it and as Xray ignores fp over QUIC (podkop-engine).
func QUICClientOptions(logger logger.Logger, options option.OutboundTLSOptions) option.OutboundTLSOptions {
	if options.UTLS == nil || !options.UTLS.Enabled {
		return options
	}
	logger.Warn("uTLS is not used over QUIC: the fingerprint ", options.UTLS.Fingerprint, " is ignored")
	options.UTLS = nil
	return options
}

// STDConfigForQUIC returns the crypto/tls form of a client config for a QUIC
// handshake, which quic-go builds itself (podkop-engine, XHTTP over HTTP/3).
// A uTLS config has no such form through STDConfig; its certificate checks
// are carried over and the fingerprint is not used, as with Xray, whose
// HTTP/3 ignores fp as well.
func STDConfigForQUIC(config Config) (*STDConfig, error) {
	if kernelTLS, isKernelTLS := config.(*KTLSClientConfig); isKernelTLS {
		config = kernelTLS.Config
	}
	if _, isECH := config.(*ECHClientConfig); isECH {
		// The list is fetched in the TCP handshake of this wrapper; without it
		// a QUIC handshake would send the server name in the clear.
		return nil, E.New("ECH with its configuration from DNS is not supported over QUIC here, set ech.config")
	}
	if converter, isConverter := config.(interface {
		quicSTDConfig() (*STDConfig, error)
	}); isConverter {
		return converter.quicSTDConfig()
	}
	return config.STDConfig()
}

package tls

import E "github.com/sagernet/sing/common/exceptions"

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

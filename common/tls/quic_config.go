package tls

// STDConfigForQUIC returns the crypto/tls form of a client config for a QUIC
// handshake, which quic-go builds itself (podkop-engine, XHTTP over HTTP/3).
// A uTLS config has no such form through STDConfig; its certificate checks
// are carried over and the fingerprint is not used, as with Xray, whose
// HTTP/3 ignores fp as well.
func STDConfigForQUIC(config Config) (*STDConfig, error) {
	if converter, isConverter := config.(interface {
		quicSTDConfig() (*STDConfig, error)
	}); isConverter {
		return converter.quicSTDConfig()
	}
	return config.STDConfig()
}

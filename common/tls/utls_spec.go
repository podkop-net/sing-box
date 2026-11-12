//go:build with_utls

package tls

import (
	"net"
	"slices"

	utls "github.com/metacubex/utls"
	"github.com/metacubex/utls/dicttls"
)

// Fingerprints Xray-core uses for "firefox" and "safari", missing from metacubex/utls
// (its Firefox 120 / Safari 16.0 carry no X25519MLKEM768 key share, which REALITY
// servers since Xray-core v26.9.8 require). Specs are ported from
// refraction-networking/utls@aa6edf4 (HelloFirefox_148, HelloSafari_26_3).
var (
	helloFirefox148 = utls.ClientHelloID{Client: "Firefox", Version: "148"}
	helloSafari26_3 = utls.ClientHelloID{Client: "Safari", Version: "26.3"}
)

func newUClient(conn net.Conn, config *utls.Config, id utls.ClientHelloID) (*utls.UConn, error) {
	var spec *utls.ClientHelloSpec
	switch {
	case id == helloFirefox148:
		spec = firefox148Spec()
	case id == helloSafari26_3:
		spec = safari26_3Spec()
	case id.Client == utls.HelloRandomizedALPN.Client:
		var err error
		spec, err = randomizedSpec(id, config.NextProtos)
		if err != nil {
			return nil, err
		}
	default:
		// By its specification, not by its ID. uTLS keeps the specification of a hello made
		// by ID for the life of the connection, and with it the extension objects that
		// releaseHandshakeState drops, the key shares among them; a custom specification
		// it does not keep. The hello is the same: uTLS makes it from this very
		// specification (TestNewUClientHelloUnchanged).
		parrot, err := utls.UTLSIdToSpec(id)
		if err != nil {
			return utls.UClient(conn, config, id), nil
		}
		// as uTLS has it for a hello made by ID (the configuration is the caller's copy)
		config.PreferSkipResumptionOnNilExtension = true
		spec = &parrot
	}
	uConn := utls.UClient(conn, config, utls.HelloCustom)
	err := uConn.ApplyPreset(spec)
	if err != nil {
		return nil, err
	}
	if id == helloFirefox148 {
		reuseHybridX25519KeyShare(uConn)
	}
	return uConn, nil
}

// randomizedSpec is the "randomized" Client Hello of this process, as uTLS builds it from
// the seed, with the X25519MLKEM768 key share sent exactly when the group is offered (as
// proposed in refraction-networking/utls#415). uTLS draws the two independently: a group
// offered without its key share makes servers preferring it (Cloudflare, Google) send a
// HelloRetryRequest that uTLS cannot answer for X25519MLKEM768 ("CurvePreferences includes
// unsupported curve"), a key share without the group is refused as an illegal parameter
// (GitHub, Apple, Microsoft); REALITY passes either reply on from its target.
func randomizedSpec(id utls.ClientHelloID, nextProtos []string) (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return nil, err
	}
	var offered bool
	for _, extension := range spec.Extensions {
		if curves, isCurves := extension.(*utls.SupportedCurvesExtension); isCurves {
			offered = slices.Contains(curves.Curves, utls.X25519MLKEM768)
		}
	}
	for _, extension := range spec.Extensions {
		switch ext := extension.(type) {
		case *utls.KeyShareExtension:
			ext.KeyShares = slices.DeleteFunc(ext.KeyShares, func(share utls.KeyShare) bool {
				return share.Group == utls.X25519MLKEM768
			})
			if offered {
				ext.KeyShares = append([]utls.KeyShare{{Group: utls.X25519MLKEM768}}, ext.KeyShares...)
			}
		case *utls.ALPNExtension:
			// UTLSIdToSpec does not know the configured protocols and offers h2 and http/1.1
			// (kept when none are configured, as for the fixed fingerprints)
			if len(nextProtos) > 0 {
				ext.AlpnProtocols = slices.Clone(nextProtos)
			}
		}
	}
	return &spec, nil
}

// reuseHybridX25519KeyShare makes the X25519 key share reuse the X25519 part of
// X25519MLKEM768, as Firefox does (refraction-networking/utls ReuseHybridAndClassicalKeyShares).
func reuseHybridX25519KeyShare(uConn *utls.UConn) {
	keys := uConn.HandshakeState.State13.KeyShareKeys
	if keys == nil || keys.MlkemEcdhe == nil {
		return
	}
	for _, extension := range uConn.Extensions {
		keyShares, isKeyShares := extension.(*utls.KeyShareExtension)
		if !isKeyShares {
			continue
		}
		for i := range keyShares.KeyShares {
			if keyShares.KeyShares[i].Group == utls.X25519 {
				keyShares.KeyShares[i].Data = keys.MlkemEcdhe.PublicKey().Bytes()
				keys.Ecdhe = keys.MlkemEcdhe
				return
			}
		}
	}
}

func firefox148Spec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []uint8{0x0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
				0x0100, // ffdhe2048
				0x0101, // ffdhe3072
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0x0}},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.FakeDelegatedCredentialsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.ECDSAWithSHA1,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519}, // reuses the hybrid's X25519 key, see reuseHybridX25519KeyShare
				{Group: utls.CurveP256},
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.ECDSAWithP521AndSHA512,
				utls.PSSWithSHA256,
				utls.PSSWithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA256,
				utls.PKCS1WithSHA384,
				utls.PKCS1WithSHA512,
				utls.ECDSAWithSHA1,
				utls.PKCS1WithSHA1,
			}},
			&utls.FakeRecordSizeLimitExtension{Limit: 0x4001},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionZlib,
				utls.CertCompressionBrotli,
				utls.CertCompressionZstd,
			}},
			&utls.GREASEEncryptedClientHelloExtension{
				CandidateCipherSuites: []utls.HPKESymmetricCipherSuite{
					{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_AES_128_GCM},
					{KdfId: dicttls.HKDF_SHA256, AeadId: dicttls.AEAD_CHACHA20_POLY1305},
				},
				CandidatePayloadLens: []uint16{223}, // +16: 239
			},
		},
	}
}

func safari26_3Spec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		CompressionMethods: []uint8{0x0},
		Extensions: []utls.TLSExtension{
			&utls.UtlsGREASEExtension{},
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.GREASE_PLACEHOLDER,
				utls.X25519MLKEM768,
				utls.X25519,
				utls.CurveP256,
				utls.CurveP384,
				utls.CurveP521,
			}},
			&utls.SupportedPointsExtension{SupportedPoints: []uint8{0x0}},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
				utls.PKCS1WithSHA1,
			}},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.GREASE_PLACEHOLDER, Data: []byte{0}},
				{Group: utls.X25519MLKEM768},
				{Group: utls.X25519},
			}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.UtlsCompressCertExtension{Algorithms: []utls.CertCompressionAlgo{
				utls.CertCompressionZlib,
			}},
			&utls.UtlsGREASEExtension{},
		},
	}
}

package sharelink

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

// The fingerprints sing-box knows by these names (common/tls/utls_client.go).
var utlsNames = map[string]bool{
	"chrome": true, "firefox": true, "edge": true, "safari": true, "360": true, "qq": true, "ios": true, "android": true,
	"random": true, "randomized": true,
	"chrome_psk": true, "chrome_psk_shuffle": true, "chrome_padding_psk_shuffle": true, "chrome_pq": true, "chrome_pq_psk": true,
}

// The fingerprints only Xray knows by name (transport/internet/tls/tls.go of Xray-core
// v26.9.30), each with the one of sing-box of the same browser. Which Client Hello a
// client imitates is the client's own choice: the server is reached with any.
var xrayFingerprints = []struct{ prefix, fingerprint string }{
	{"hellochrome_", "chrome"},
	{"hellofirefox_", "firefox"},
	{"hellosafari_", "safari"},
	{"helloios_", "ios"},
	{"helloedge_", "edge"},
	{"hello360_", "360"},
	{"helloqq_", "qq"},
	{"helloandroid_", "android"},
	{"hellorandomized", "randomized"},
	{"randomizednoalpn", "randomized"},
}

// utls reads the fingerprint of a link as Xray does: any case, Chrome's when there is
// none, and no imitation for "unsafe" and for a name Xray does not know (not with
// REALITY, which is built on uTLS and refuses both).
func (d *decoder) utls(reality bool) (*option.OutboundUTLSOptions, error) {
	return d.utlsOf(d.query["fp"], reality)
}

func (d *decoder) utlsOf(fingerprint string, reality bool) (*option.OutboundUTLSOptions, error) {
	fingerprint = strings.ToLower(fingerprint)
	switch {
	case fingerprint == "":
		fingerprint = "chrome"
	case utlsNames[fingerprint]:
	case (fingerprint == "unsafe" || fingerprint == "hellogolang") && !reality:
		return nil, nil
	default:
		substitute := ""
		for _, known := range xrayFingerprints {
			if strings.HasPrefix(fingerprint, known.prefix) {
				substitute = known.fingerprint
				break
			}
		}
		switch {
		case substitute != "":
			d.warn("the fingerprint", shown(fingerprint), " has no counterpart, ", substitute, " is used")
			fingerprint = substitute
		case reality:
			return nil, refuse("fingerprint-reality", "unsupported fingerprint", shown(fingerprint), ", which REALITY needs")
		default:
			d.warn("the fingerprint", shown(fingerprint), " is unknown, no browser is imitated")
			return nil, nil
		}
	}
	return &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint}, nil
}

// The parameters of TLS every scheme reads the same way. With REALITY no certificate is
// verified, and a pin the link carries along is left out without a word.
func (d *decoder) tlsCommon(tlsOptions *option.OutboundTLSOptions, reality bool) {
	d.reads("sni", "servername", "peer", "allowinsecure", "allow_insecure", "insecure", "skip-cert-verify",
		"alpn", "disable_sni", "nosni", "cert", "ech", "pcs", "pinsha256", "vcn", "cs")
	tlsOptions.Enabled = true
	if tlsOptions.ServerName == "" {
		tlsOptions.ServerName = d.first("sni", "servername", "peer")
	}
	tlsOptions.Insecure = isTrue(d.first("allowinsecure", "allow_insecure", "insecure", "skip-cert-verify"))
	if alpn := splitList(d.query["alpn"]); len(alpn) > 0 {
		tlsOptions.ALPN = alpn
	}
	tlsOptions.DisableSNI = isTrue(d.first("disable_sni", "nosni"))
	if certificate := strings.TrimSpace(d.query["cert"]); certificate != "" {
		// the certificate to trust, in the link itself (NekoBox, husi)
		tlsOptions.Certificate = strings.Split(strings.ReplaceAll(certificate, "\r\n", "\n"), "\n")
	}
	tlsOptions.ECH = d.ech()
	if !reality {
		d.verification(tlsOptions, d.first("pcs", "pinsha256"), d.query["vcn"])
	}
	if d.query["cs"] != "" {
		d.warn("cs (the cipher suites of TLS) is not supported and is ignored")
	}
}

// ech reads the "ech" of a link: the ECH configuration list in base64 or, as Xray takes
// it, where to ask for it: a resolver, or a name and a resolver joined with "+".
func (d *decoder) ech() *option.OutboundECHOptions {
	// form decoding has made a space of every "+"
	value := strings.ReplaceAll(strings.TrimSpace(d.query["ech"]), " ", "+")
	if value == "" {
		return nil
	}
	if strings.Contains(value, "://") {
		echOptions := &option.OutboundECHOptions{Enabled: true}
		if name, _, named := strings.Cut(value, "+"); named && !strings.Contains(name, "://") {
			echOptions.QueryServerName = strings.TrimSpace(name)
		}
		d.warn("the resolver named in ech is not used: the ECH configuration is asked from the DNS of sing-box")
		return echOptions
	}
	var list []byte
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			list = decoded
			break
		}
	}
	if len(list) == 0 {
		d.warn("ech is neither a configuration list in base64 nor a resolver, and is ignored")
		return nil
	}
	lines := []string{"-----BEGIN ECH CONFIGS-----"}
	encoded := base64.StdEncoding.EncodeToString(list)
	for len(encoded) > 64 {
		lines = append(lines, encoded[:64])
		encoded = encoded[64:]
	}
	lines = append(lines, encoded, "-----END ECH CONFIGS-----")
	return &option.OutboundECHOptions{Enabled: true, Config: lines}
}

// security reads the TLS of a link of the VLESS family (the proposal of Xray-core
// discussion #716): "security" chooses none, TLS or REALITY.
func (d *decoder) security(defaultSecurity string) (*option.OutboundTLSOptions, error) {
	// also the ones a link without TLS carries along: the generators write them anyway
	d.reads("security", "fp", "pbk", "sid", "pqv", "spx", "spiderx",
		"sni", "servername", "peer", "allowinsecure", "allow_insecure", "insecure", "skip-cert-verify",
		"alpn", "disable_sni", "nosni", "cert", "ech", "pcs", "pinsha256", "vcn", "cs")
	security := strings.ToLower(d.query["security"])
	if security == "" {
		security = defaultSecurity
	}
	switch security {
	case "none":
		return nil, nil
	case "tls", "reality":
	default:
		return nil, refuse("security", "unsupported security", shown(security))
	}
	tlsOptions := new(option.OutboundTLSOptions)
	d.tlsCommon(tlsOptions, security == "reality")
	var err error
	tlsOptions.UTLS, err = d.utls(security == "reality")
	if err != nil {
		return nil, err
	}
	if security == "reality" {
		if d.query["pbk"] == "" {
			return nil, E.New("missing REALITY public key (pbk)")
		}
		if shortID := d.query["sid"]; len(shortID) > 16 || len(shortID)%2 != 0 || !isHex(shortID) {
			return nil, E.New("the REALITY short id (sid) is not hexadecimal digits, up to 16 and an even number of them")
		}
		tlsOptions.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: d.query["pbk"],
			ShortID:   d.query["sid"],
		}
		if d.query["pqv"] != "" {
			d.warn("pqv (the ML-DSA-65 check of the REALITY server) is not supported, the server is not verified with it")
		}
	}
	return tlsOptions, nil
}

// tlsAlways reads the TLS of a link whose protocol always runs over TLS or QUIC. There
// is no fingerprint to imitate: over QUIC sing-box has none, and the schemes that carry
// "fp" read it themselves.
func (d *decoder) tlsAlways() *option.OutboundTLSOptions {
	tlsOptions := new(option.OutboundTLSOptions)
	d.tlsCommon(tlsOptions, false)
	return tlsOptions
}

// certificateHashes reads the pins of Xray's pcs and Hysteria's pinSHA256: SHA-256 hashes in
// hexadecimal, with or without colons, separated by commas (infra/conf of Xray-core). The
// message names no hash: a pin is part of the link.
// verification reads how Xray and Hysteria verify the server's certificate, as this engine
// verifies it too (podkop-engine, 0702): pins (pcs, pinnedPeerCertSha256 of Xray; pinSHA256 of
// Hysteria) are the SHA-256 of a whole certificate, the leaf or a CA of the chain, as
// certificate_sha256 takes them; the pin is the check, with insecure as well (Hysteria checks it
// then, and Xray no longer has insecure). vcn (verifyPeerCertByName) names what the certificate
// is verified by instead of the name sent, as certificate_server_name does. With a certificate of
// the link a pin is not taken: that certificate is the root.
func (d *decoder) verification(tlsOptions *option.OutboundTLSOptions, pins string, names string) {
	if pins != "" && len(tlsOptions.Certificate) == 0 {
		hashes, err := certificateHashes(pins)
		if err != nil {
			if tlsOptions.Insecure {
				d.warn("the pinned certificate (pcs, pinSHA256) cannot be read and is ignored (", err.Error(), "): the server is not verified")
			} else {
				d.warn("the pinned certificate (pcs, pinSHA256) cannot be read and is ignored (", err.Error(), "): the server is verified against the system roots")
			}
		} else {
			tlsOptions.CertificateSHA256 = hashes
			tlsOptions.Insecure = false
		}
	}
	if list := splitList(names); len(list) > 0 && !tlsOptions.Insecure {
		same := true
		for _, name := range list {
			same = same && strings.EqualFold(name, tlsOptions.ServerName)
		}
		if !same {
			tlsOptions.CertificateServerName = list
		}
	}
}

func certificateHashes(text string) (badoption.Listable[[]byte], error) {
	var hashes badoption.Listable[[]byte]
	for _, entry := range strings.Split(text, ",") {
		// OpenSSL's colons; Hysteria takes dashes too
		entry = strings.NewReplacer(":", "", "-", "").Replace(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		hash, err := hex.DecodeString(entry)
		if err != nil {
			return nil, E.New("a hash is not hexadecimal")
		}
		if len(hash) != sha256.Size {
			return nil, E.New("a hash is not 32 bytes long")
		}
		hashes = append(hashes, hash)
	}
	if len(hashes) == 0 {
		return nil, E.New("no hash")
	}
	return hashes, nil
}

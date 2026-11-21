package tls

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"slices"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// checkCertificateServerName refuses certificate_server_name with insecure, which skips the
// verification it is for, and an empty name (podkop-engine).
func checkCertificateServerName(options option.OutboundTLSOptions) error {
	if len(options.CertificateServerName) == 0 {
		return nil
	}
	if options.Insecure {
		return E.New("certificate_server_name is conflict with insecure")
	}
	for _, name := range options.CertificateServerName {
		if strings.TrimSpace(name) == "" {
			return E.New("certificate_server_name has an empty name")
		}
	}
	return nil
}

// peerVerifier verifies the server's certificate the way Xray's client does (podkop-engine;
// transport/internet/tls/config.go, verifyPeerCert and verifyChain), when a pin or
// certificate_server_name is set:
//   - a pinned leaf (certificate_sha256 or certificate_public_key_sha256) is taken by itself,
//     whatever its names and its issuer are, as upstream's VerifyPinnedCertificate takes it;
//   - a pinned certificate above the leaf that is a CA becomes the only root: the chain is
//     verified to it (a pin that lives through the renewals of the leaf);
//   - the names verified are those of certificate_server_name, or the server name; the
//     handshake still sends the server name.
//
// Without a pin, the roots are the configured ones (the system's, or those of certificate).
type peerVerifier struct {
	roots             *x509.CertPool
	timeFunc          func() time.Time
	certificateHashes [][]byte
	publicKeyHashes   [][]byte
	names             []string
}

// newPeerVerifier returns nil when the default verification stands: neither a pin nor
// certificate_server_name.
func newPeerVerifier(options option.OutboundTLSOptions, roots *x509.CertPool, timeFunc func() time.Time) *peerVerifier {
	if len(options.CertificateSHA256) == 0 && len(options.CertificatePublicKeySHA256) == 0 && len(options.CertificateServerName) == 0 {
		return nil
	}
	return &peerVerifier{
		roots:             roots,
		timeFunc:          timeFunc,
		certificateHashes: options.CertificateSHA256,
		publicKeyHashes:   options.CertificatePublicKeySHA256,
		names:             options.CertificateServerName,
	}
}

// forName is the VerifyPeerCertificate of a connection to serverName.
func (v *peerVerifier) forName(serverName string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		return v.verify(rawCerts, serverName)
	}
}

func (v *peerVerifier) verify(rawCerts [][]byte, serverName string) error {
	if len(rawCerts) == 0 {
		return E.New("missing peer certificate")
	}
	roots := v.roots
	if len(v.certificateHashes) > 0 || len(v.publicKeyHashes) > 0 {
		pinErr := VerifyPinnedCertificate(v.certificateHashes, v.publicKeyHashes, rawCerts)
		if pinErr == nil {
			return nil
		}
		authority := v.pinnedAuthority(rawCerts[1:])
		if authority == nil {
			return pinErr
		}
		roots = x509.NewCertPool()
		roots.AddCert(authority)
	}
	names := v.names
	if len(names) == 0 {
		if serverName == "" {
			return E.New("a pinned certificate authority needs a server name to verify by")
		}
		names = []string{serverName}
	}
	certificates := make([]*x509.Certificate, 0, len(rawCerts))
	for _, rawCert := range rawCerts {
		certificate, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return E.Cause(err, "parse peer certificate")
		}
		certificates = append(certificates, certificate)
	}
	var lastErr error
	for _, name := range names {
		lastErr = verifySystemTLSPeer(roots, name, v.timeFunc, certificates)
		if lastErr == nil {
			return nil
		}
	}
	if len(v.names) > 0 {
		return E.Cause(lastErr, "verify the certificate for certificate_server_name")
	}
	return E.Cause(lastErr, "verify the certificate against the pinned certificate authority")
}

// pinnedAuthority finds the certificate of the chain above the leaf whose certificate_sha256 is
// pinned and that is a CA (Xray's foundCA).
func (v *peerVerifier) pinnedAuthority(rawCerts [][]byte) *x509.Certificate {
	for _, rawCert := range rawCerts {
		hash := sha256.Sum256(rawCert)
		if !slices.ContainsFunc(v.certificateHashes, func(value []byte) bool { return bytes.Equal(value, hash[:]) }) {
			continue
		}
		certificate, err := x509.ParseCertificate(rawCert)
		if err == nil && certificate.IsCA {
			return certificate
		}
	}
	return nil
}

package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// sniRecorder keeps the server names the test server was asked for.
type sniRecorder struct {
	access sync.Mutex
	names  []string
}

func (r *sniRecorder) config(certificate stdtls.Certificate) *stdtls.Config {
	return &stdtls.Config{
		Certificates: []stdtls.Certificate{certificate},
		GetConfigForClient: func(hello *stdtls.ClientHelloInfo) (*stdtls.Config, error) {
			r.access.Lock()
			r.names = append(r.names, hello.ServerName)
			r.access.Unlock()
			return nil, nil
		},
	}
}

func (r *sniRecorder) last() string {
	r.access.Lock()
	defer r.access.Unlock()
	if len(r.names) == 0 {
		return "<none>"
	}
	return r.names[len(r.names)-1]
}

// testAuthority is a CA and a leaf for real.example it signed: the chain a server sends.
type testAuthority struct {
	certificate *x509.Certificate
	leaf        stdtls.Certificate
	pem         string
}

func newTestAuthority(t *testing.T) testAuthority {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "real.example"}, DNSNames: []string{"real.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	return testAuthority{
		certificate: ca,
		leaf:        stdtls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey},
		pem:         string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
	}
}

// testCertificateServerName dials a server whose certificate is for real.example by the name
// front.example: verified by the server name it is refused, by certificate_server_name it is
// taken when one of the names is that of the certificate, and the handshake still sends
// front.example.
func testCertificateServerName(t *testing.T, utls *option.OutboundUTLSOptions) {
	serverCertificate := newPinnedTestCertificate(t, "real.example")
	recorder := &sniRecorder{}
	serverConfig := recorder.config(serverCertificate.Certificate)
	base := func() option.OutboundTLSOptions {
		return option.OutboundTLSOptions{
			Enabled:     true,
			ServerName:  "front.example",
			Certificate: badoption.Listable[string]{serverCertificate.certificatePEM},
			UTLS:        utls,
		}
	}

	require.Error(t, dialPinnedTestServer(t, serverConfig, base()), "verified by the server name")
	require.Equal(t, "front.example", recorder.last())

	options := base()
	options.CertificateServerName = badoption.Listable[string]{"other.example", "real.example"}
	require.NoError(t, dialPinnedTestServer(t, serverConfig, options), "one of the names is the certificate's")
	require.Equal(t, "front.example", recorder.last(), "the server name is still sent")

	options = base()
	options.CertificateServerName = badoption.Listable[string]{"wrong.example"}
	require.ErrorContains(t, dialPinnedTestServer(t, serverConfig, options), "certificate_server_name", "none of the names is the certificate's")

	options = base()
	options.CertificateServerName = badoption.Listable[string]{"real.example"}
	options.Certificate = nil
	require.ErrorContains(t, dialPinnedTestServer(t, serverConfig, options), "certificate_server_name", "the chain is still verified: the system roots do not have it")

	options = base()
	options.DisableSNI = true
	options.CertificateServerName = badoption.Listable[string]{"real.example"}
	require.NoError(t, dialPinnedTestServer(t, serverConfig, options), "without SNI, verified by the names")
	require.Equal(t, "", recorder.last())

	options = base()
	options.DisableSNI = true
	options.CertificateServerName = badoption.Listable[string]{"wrong.example"}
	require.ErrorContains(t, dialPinnedTestServer(t, serverConfig, options), "certificate_server_name", "without SNI, a wrong name is refused")
}

// testPinnedAuthority: a pin of the CA in the chain, as Xray takes pinnedPeerCertSha256, and
// a pinned self-signed leaf without SNI.
func testPinnedAuthority(t *testing.T, utls *option.OutboundUTLSOptions) {
	authority := newTestAuthority(t)
	serverConfig := &stdtls.Config{Certificates: []stdtls.Certificate{authority.leaf}}
	caHash := sha256.Sum256(authority.certificate.Raw)
	otherHash := sha256.Sum256([]byte("another certificate"))
	pinned := func(serverName string, names ...string) option.OutboundTLSOptions {
		return option.OutboundTLSOptions{
			Enabled: true, ServerName: serverName, UTLS: utls,
			CertificateSHA256:     badoption.Listable[[]byte]{otherHash[:], caHash[:]},
			CertificateServerName: names,
		}
	}
	require.NoError(t, dialPinnedTestServer(t, serverConfig, pinned("real.example")), "the chain verified to the pinned CA by the server name")
	require.ErrorContains(t, dialPinnedTestServer(t, serverConfig, pinned("front.example")), "pinned certificate authority", "the pinned CA, but not the name")
	require.NoError(t, dialPinnedTestServer(t, serverConfig, pinned("front.example", "real.example")), "the pinned CA and certificate_server_name")

	options := pinned("real.example")
	options.CertificateSHA256 = badoption.Listable[[]byte]{otherHash[:]}
	require.ErrorContains(t, dialPinnedTestServer(t, serverConfig, options), "unrecognized peer certificate", "no certificate of the chain is pinned")

	// a pinned self-signed leaf is taken whatever its name, with or without SNI
	selfSigned := newPinnedTestCertificate(t, "localhost")
	leafHash := sha256.Sum256(selfSigned.Leaf.Raw)
	selfConfig := &stdtls.Config{Certificates: []stdtls.Certificate{selfSigned.Certificate}}
	for _, disableSNI := range []bool{false, true} {
		require.NoError(t, dialPinnedTestServer(t, selfConfig, option.OutboundTLSOptions{
			Enabled: true, ServerName: "front.example", DisableSNI: disableSNI, UTLS: utls,
			CertificateSHA256: badoption.Listable[[]byte]{leafHash[:]},
		}), "a pinned leaf, disable_sni %v", disableSNI)
	}
}

func TestClientCertificateServerName(t *testing.T) {
	t.Parallel()
	testCertificateServerName(t, nil)
}

func TestClientPinnedAuthority(t *testing.T) {
	t.Parallel()
	testPinnedAuthority(t, nil)
}

func TestCertificateServerNameConflicts(t *testing.T) {
	t.Parallel()
	for name, options := range map[string]option.OutboundTLSOptions{
		"insecure":      {Enabled: true, ServerName: "a.example", Insecure: true, CertificateServerName: badoption.Listable[string]{"b.example"}},
		"an empty name": {Enabled: true, ServerName: "a.example", CertificateServerName: badoption.Listable[string]{" "}},
	} {
		_, err := NewClientWithOptions(ClientOptions{Context: context.Background(), Logger: logger.NOP(), Options: options})
		require.ErrorContains(t, err, "certificate_server_name", name)
	}
}

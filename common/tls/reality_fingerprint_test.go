//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

type warnLog struct {
	access sync.Mutex
	lines  []string
}

func (l *warnLog) WriteMessage(level log.Level, message string) {
	if level != log.LevelWarn {
		return
	}
	l.access.Lock()
	defer l.access.Unlock()
	l.lines = append(l.lines, message)
}

func (l *warnLog) take() []string {
	l.access.Lock()
	defer l.access.Unlock()
	lines := l.lines
	l.lines = nil
	return lines
}

func newWarnLogger(t *testing.T) (log.ContextLogger, *warnLog) {
	writer := &warnLog{}
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now()}, io.Discard, "", writer, false)
	factory.SetLevel(log.LevelDebug)
	require.NoError(t, factory.Start())
	t.Cleanup(func() { factory.Close() })
	return factory.NewLogger("tls"), writer
}

func realityOptionsForTest(fingerprint string, reality bool) option.OutboundTLSOptions {
	options := option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.org",
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
	}
	if reality {
		serverKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
		options.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: base64.RawURLEncoding.EncodeToString(serverKey.PublicKey().Bytes()),
			ShortID:   "0123456789abcdef",
		}
	}
	return options
}

// The fingerprints of TLS 1.2 have no key share for REALITY to derive its key from: the
// configuration is refused and the error names the fingerprint. Without REALITY they stay
// usable.
func TestRealityFingerprintWithoutKeyShareRefused(t *testing.T) {
	for _, fingerprint := range []string{"android", "360"} {
		t.Run(fingerprint, func(t *testing.T) {
			logger, _ := newWarnLogger(t)
			_, err := NewClient(context.Background(), logger, "example.org", realityOptionsForTest(fingerprint, true))
			require.Error(t, err)
			require.Contains(t, err.Error(), "uTLS fingerprint "+fingerprint+" ")
			require.Contains(t, err.Error(), "reality")

			_, err = NewClient(context.Background(), logger, "example.org", realityOptionsForTest(fingerprint, false))
			require.NoError(t, err)
		})
	}
}

// The fingerprints with an X25519 key share only work with older REALITY servers: one
// warning at creation names the fingerprint and the requirement. The fingerprints with the
// hybrid key share, and any fingerprint without REALITY, warn about nothing.
func TestRealityFingerprintWithoutHybridKeyShareWarns(t *testing.T) {
	for _, testCase := range []struct {
		fingerprint string
		reality     bool
		warns       bool
	}{
		{"edge", true, true},
		{"ios", true, true},
		{"qq", true, true},
		{"", true, false},
		{"chrome", true, false},
		{"firefox", true, false},
		{"safari", true, false},
		{"random", true, false},
		{"randomized", true, false},
		{"edge", false, false},
		{"ios", false, false},
		{"qq", false, false},
	} {
		name := testCase.fingerprint
		if name == "" {
			name = "default"
		}
		if !testCase.reality {
			name += " without reality"
		}
		t.Run(name, func(t *testing.T) {
			logger, writer := newWarnLogger(t)
			config, err := NewClient(context.Background(), logger, "example.org", realityOptionsForTest(testCase.fingerprint, testCase.reality))
			require.NoError(t, err)
			// a copy, which every connection of some transports takes, does not warn again
			config.Clone()
			lines := writer.take()
			if !testCase.warns {
				require.Empty(t, lines)
				return
			}
			require.Len(t, lines, 1)
			require.Contains(t, lines[0], "uTLS fingerprint "+testCase.fingerprint+" ")
			require.Contains(t, lines[0], "X25519MLKEM768")
			require.Contains(t, lines[0], "Xray-core v26.9.8")
		})
	}
}

// trustedServerCertificate is a certificate for example.org that the system verifier of
// this process accepts: REALITY verifies the certificate of a server that did not
// authenticate against the system roots, which a test can add to only through
// SSL_CERT_FILE and only before their first use: a test of this package that verifies
// against the system roots calls this first. From then on the roots of the test process
// are this test root and the certificates of the system directories.
var trustedServerCertificate = sync.OnceValues(func() (tls.Certificate, bool) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, false
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return tls.Certificate{}, false
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, false
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "example.org"},
		DNSNames:     []string{"example.org"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	if err != nil {
		return tls.Certificate{}, false
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return tls.Certificate{}, false
	}

	directory, err := os.MkdirTemp("", "reality-roots")
	if err != nil {
		return tls.Certificate{}, false
	}
	defer os.RemoveAll(directory)
	rootsPath := filepath.Join(directory, "roots.pem")
	err = os.WriteFile(rootsPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0o600)
	if err != nil {
		return tls.Certificate{}, false
	}
	savedFile, hadFile := os.LookupEnv("SSL_CERT_FILE")
	os.Setenv("SSL_CERT_FILE", rootsPath)
	defer func() {
		if hadFile {
			os.Setenv("SSL_CERT_FILE", savedFile)
		} else {
			os.Unsetenv("SSL_CERT_FILE")
		}
	}()
	// loads the system roots, unless something has loaded them before
	_, err = leaf.Verify(x509.VerifyOptions{DNSName: "example.org"})
	if err != nil {
		return tls.Certificate{}, false
	}
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey, Leaf: leaf}, true
})

// plainTLSServer answers one connection as the target of a REALITY server does for a
// client it did not recognise: a TLS handshake with its own certificate.
func plainTLSServer(t *testing.T, conn net.Conn, certificate tls.Certificate) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer conn.Close()
		serverConn := tls.Server(conn, &tls.Config{
			Certificates:           []tls.Certificate{certificate},
			SessionTicketsDisabled: true,
		})
		if serverConn.Handshake() != nil {
			return
		}
		io.Copy(io.Discard, serverConn)
	}()
	t.Cleanup(func() {
		conn.Close()
		<-done
	})
}

// A server that takes the Client Hello for a stranger's hands the connection to its target,
// and the client sees a valid certificate that is not the server's. With a fingerprint that
// lacks the hybrid key share the error says that the fingerprint may be the cause.
func TestRealityVerificationFailureNamesFingerprint(t *testing.T) {
	certificate, trusted := trustedServerCertificate()
	if !trusted {
		if runtime.GOOS == "linux" {
			// a skip would go unnoticed, and nothing else tests the text of this error
			t.Fatal("the system roots of this process cannot be set: were they loaded by an earlier test?")
		}
		t.Skip("the system roots of this process cannot be set")
	}
	for _, testCase := range []struct {
		fingerprint string
		named       bool
	}{
		{"ios", true},
		{"edge", true},
		{"qq", true},
		{"chrome", false},
	} {
		t.Run(testCase.fingerprint, func(t *testing.T) {
			logger, _ := newWarnLogger(t)
			config, err := NewClient(context.Background(), logger, "example.org", realityOptionsForTest(testCase.fingerprint, true))
			require.NoError(t, err)
			client, server := net.Pipe()
			defer client.Close()
			plainTLSServer(t, server, certificate)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			// a copy, as the transports that set their own ALPN make
			_, err = ClientHandshake(ctx, client, config.Clone())
			require.Error(t, err)
			require.True(t, strings.HasPrefix(err.Error(), "reality verification failed"), err.Error())
			if !testCase.named {
				require.Equal(t, "reality verification failed", err.Error())
				return
			}
			require.Contains(t, err.Error(), "uTLS fingerprint "+testCase.fingerprint+":")
			require.Contains(t, err.Error(), "X25519MLKEM768")
			require.Contains(t, err.Error(), "Xray-core v26.9.8")
		})
	}
}

// The certificate of the target may also be one this host does not accept (no CA bundle, a
// clock that is not set yet): the handshake then fails on the certificate, and the error
// names the fingerprint as well. Other fingerprints keep the bare error.
func TestRealityRejectedCertificateNamesFingerprint(t *testing.T) {
	// this test verifies against the system roots too and must not load them first
	trustedServerCertificate()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.org"},
		DNSNames:     []string{"example.org"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	for _, testCase := range []struct {
		fingerprint string
		named       bool
	}{
		{"ios", true},
		{"edge", true},
		{"qq", true},
		{"chrome", false},
	} {
		t.Run(testCase.fingerprint, func(t *testing.T) {
			logger, _ := newWarnLogger(t)
			config, err := NewClient(context.Background(), logger, "example.org", realityOptionsForTest(testCase.fingerprint, true))
			require.NoError(t, err)
			// a socket, not a pipe: the alert of the client and the rest of the server's
			// flight cross on the way, and a pipe buffers neither
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()
			client, err := net.Dial("tcp", listener.Addr().String())
			require.NoError(t, err)
			defer client.Close()
			server, err := listener.Accept()
			require.NoError(t, err)
			plainTLSServer(t, server, certificate)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_, err = ClientHandshake(ctx, client, config.Clone())
			require.Error(t, err)
			require.Contains(t, err.Error(), "x509: ")
			if !testCase.named {
				require.NotContains(t, err.Error(), "uTLS fingerprint")
				require.NotContains(t, err.Error(), "reality verification failed")
				return
			}
			require.True(t, strings.HasPrefix(err.Error(), "reality verification failed"), err.Error())
			require.Contains(t, err.Error(), "uTLS fingerprint "+testCase.fingerprint+":")
			require.Contains(t, err.Error(), "Xray-core v26.9.8")
		})
	}
}

// The handshake state is released once the handshake is done. A second HandshakeContext
// on a connection with ALPN has no Client Hello to rebuild and reports the finished
// handshake instead.
func TestUTLSALPNHandshakeAgainAfterRelease(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.org"},
		DNSNames:     []string{"example.org"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)

	options := realityOptionsForTest("chrome", false)
	options.Insecure = true
	options.ALPN = []string{"h2", "http/1.1"}
	config, err := NewClient(context.Background(), nil, "example.org", options)
	require.NoError(t, err)
	client, server := net.Pipe()
	defer client.Close()
	plainTLSServer(t, server, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: rootKey})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := config.Client(client)
	require.NoError(t, err)
	require.IsType(t, &utlsALPNWrapper{}, conn)
	require.NoError(t, conn.HandshakeContext(ctx))
	require.Nil(t, conn.(*utlsALPNWrapper).HandshakeState.Hello)
	require.NotPanics(t, func() {
		require.NoError(t, conn.HandshakeContext(ctx))
	})
	require.True(t, conn.ConnectionState().HandshakeComplete)
}

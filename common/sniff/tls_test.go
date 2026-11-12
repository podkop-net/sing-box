package sniff_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

// captureClientHello records the first TLS record a client writes: its ClientHello.
func captureClientHello(t testing.TB, handshake func(net.Conn)) []byte {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		handshake(clientConn)
		clientConn.Close()
	}()
	buffer := make([]byte, 16384)
	n, err := io.ReadAtLeast(serverConn, buffer, 5)
	require.NoError(t, err)
	recordLength := int(buffer[3])<<8 | int(buffer[4])
	for n < 5+recordLength {
		m, err := serverConn.Read(buffer[n:])
		require.NoError(t, err)
		n += m
	}
	return append([]byte(nil), buffer[:5+recordLength]...)
}

func stdClientHello(t testing.TB, config *tls.Config) []byte {
	return captureClientHello(t, func(conn net.Conn) { tls.Client(conn, config).Handshake() })
}

func uTLSClientHello(t testing.TB, id utls.ClientHelloID, serverName string) []byte {
	return captureClientHello(t, func(conn net.Conn) {
		utls.UClient(conn, &utls.Config{ServerName: serverName, InsecureSkipVerify: true}, id).Handshake()
	})
}

// splitRecords re-frames one handshake record into records of at most size payload bytes:
// a handshake message may span records, and clients that fragment the ClientHello against
// DPI do exactly that.
func splitRecords(record []byte, size int) []byte {
	header, payload := record[:5], record[5:]
	var out []byte
	for len(payload) > 0 {
		n := min(size, len(payload))
		out = append(out, header[0], header[1], header[2], byte(n>>8), byte(n))
		out = append(out, payload[:n]...)
		payload = payload[n:]
	}
	return out
}

func TestSniffTLSClientHello(t *testing.T) {
	t.Parallel()
	const serverName = "www.example.com"
	hellos := map[string][]byte{
		"go, TLS 1.3 with a post-quantum key share": stdClientHello(t, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}),
		"go, TLS 1.2 only":                          stdClientHello(t, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}),
		"go, X25519 only":                           stdClientHello(t, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.X25519}}),
		"go, P-256 only":                            stdClientHello(t, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.CurveP256}}),
		"go, ALPN":                                  stdClientHello(t, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}}),
		"utls Chrome":                               uTLSClientHello(t, utls.HelloChrome_Auto, serverName),
		"utls Firefox":                              uTLSClientHello(t, utls.HelloFirefox_Auto, serverName),
		"utls Safari":                               uTLSClientHello(t, utls.HelloSafari_Auto, serverName),
		"utls iOS":                                  uTLSClientHello(t, utls.HelloIOS_Auto, serverName),
		"utls Edge":                                 uTLSClientHello(t, utls.HelloEdge_Auto, serverName),
		"utls randomized":                           uTLSClientHello(t, utls.HelloRandomizedALPN, serverName),
	}
	chrome := hellos["utls Chrome"]
	hellos["utls Chrome, split into 2 records"] = splitRecords(chrome, (len(chrome)-5)/2+1)
	hellos["utls Chrome, split into 100-byte records"] = splitRecords(chrome, 100)

	for name, hello := range hellos {
		var metadata adapter.InboundContext
		err := sniff.TLSClientHello(context.Background(), &metadata, bytes.NewReader(hello))
		require.NoError(t, err, name)
		require.Equal(t, C.ProtocolTLS, metadata.Protocol, name)
		require.Equal(t, serverName, metadata.Domain, name)
	}

	// TLS without SNI is still TLS, for protocol rules
	var metadata adapter.InboundContext
	err := sniff.TLSClientHello(context.Background(), &metadata, bytes.NewReader(stdClientHello(t, &tls.Config{InsecureSkipVerify: true})))
	require.NoError(t, err)
	require.Equal(t, C.ProtocolTLS, metadata.Protocol)
	require.Empty(t, metadata.Domain)

	// an incomplete hello asks for more data
	for _, cut := range []int{5, len(chrome) / 2, len(chrome) - 1} {
		var metadata adapter.InboundContext
		err := sniff.TLSClientHello(context.Background(), &metadata, bytes.NewReader(chrome[:cut]))
		require.ErrorIs(t, err, sniff.ErrNeedMoreData, "cut at %d", cut)
		require.Empty(t, metadata.Protocol)
	}

	// what is not TLS is refused
	for name, input := range map[string][]byte{
		"http request": []byte("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"),
		"garbage":      bytes.Repeat([]byte{0x16, 0x03, 0x01, 0xff}, 64),
	} {
		var metadata adapter.InboundContext
		err := sniff.TLSClientHello(context.Background(), &metadata, bytes.NewReader(input))
		require.Error(t, err, name)
		require.False(t, errors.Is(err, sniff.ErrNeedMoreData), name)
		require.Empty(t, metadata.Protocol, name)
	}
}

func BenchmarkSniffTLSClientHello(b *testing.B) {
	hello := uTLSClientHello(b, utls.HelloChrome_Auto, "www.example.com")
	b.ReportAllocs()
	for b.Loop() {
		var metadata adapter.InboundContext
		sniff.TLSClientHello(context.Background(), &metadata, bytes.NewReader(hello))
	}
}

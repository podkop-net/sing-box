package ja3

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// clientHello makes a TLS record with a ClientHello that carries one extension.
func clientHello(extensionType uint16, extensionData []byte) []byte {
	extension := binary.BigEndian.AppendUint16(nil, extensionType)
	extension = binary.BigEndian.AppendUint16(extension, uint16(len(extensionData)))
	extension = append(extension, extensionData...)
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, randomDataLen)...)
	body = append(body, 0)                // session ID
	body = append(body, 0, 2, 0x13, 0x01) // cipher suites
	body = append(body, 1, 0)             // compression methods
	body = binary.BigEndian.AppendUint16(body, uint16(len(extension)))
	body = append(body, extension...)
	handshake := append([]byte{handshakeType, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{contentType, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
}

// A list length past the end of its extension is an error, not a panic: the QUIC sniffer
// parses ClientHellos that any client in the LAN can send.
func TestComputeListLengthPastExtension(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		extensionType uint16
		data          []byte
	}{
		{"supported_versions", versionExtensionType, []byte{0xfe, 0x03, 0x04}},
		{"signature_algorithms", signatureAlgorithmsExtensionType, []byte{0xff, 0xff, 0x04, 0x03}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Compute(clientHello(testCase.extensionType, testCase.data))
			require.Error(t, err)
		})
	}
	hello, err := Compute(clientHello(versionExtensionType, []byte{0x02, 0x03, 0x04}))
	require.NoError(t, err)
	require.Equal(t, []uint16{tls13}, hello.Versions)
	hello, err = Compute(clientHello(signatureAlgorithmsExtensionType, []byte{0x00, 0x02, 0x04, 0x03}))
	require.NoError(t, err)
	require.Equal(t, []uint16{0x0403}, hello.SignatureAlgorithms)
}

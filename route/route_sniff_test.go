package route

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/sagernet/sing-box/log"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

// quicInitialSaltV1 is the public salt of QUIC v1 Initial keys (RFC 9001, section 5.2).
var quicInitialSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

func hkdfExpandLabel(t *testing.T, secret []byte, label string, length int) []byte {
	fullLabel := "tls13 " + label
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, 0)
	out := make([]byte, length)
	_, err := io.ReadFull(hkdf.Expand(sha256.New, secret, info), out)
	require.NoError(t, err)
	return out
}

// quicInitial seals a client Initial packet of QUIC v1 with one CRYPTO frame of data at
// offset.
func quicInitial(t *testing.T, offset uint64, data []byte) []byte {
	destination := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	secret := hkdfExpandLabel(t, hkdf.Extract(sha256.New, destination, quicInitialSaltV1), "client in", sha256.Size)
	key := hkdfExpandLabel(t, secret, "quic key", 16)
	iv := hkdfExpandLabel(t, secret, "quic iv", 12)
	headerKey := hkdfExpandLabel(t, secret, "quic hp", 16)

	payload := []byte{0x06, 0x80 | byte(offset>>24), byte(offset >> 16), byte(offset >> 8), byte(offset)}
	payload = append(payload, 0x40|byte(len(data)>>8), byte(len(data)))
	payload = append(payload, data...)
	header := []byte{0xc0, 0, 0, 0, 1, byte(len(destination))}
	header = append(header, destination...)
	header = append(header, 0, 0) // source connection ID, token
	length := 1 + len(payload) + 16
	header = append(header, 0x40|byte(length>>8), byte(length))
	numberOffset := len(header)
	header = append(header, 0) // packet number 0, its nonce is the IV

	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	packet := aead.Seal(append([]byte{}, header...), iv, payload, header)
	headerBlock, err := aes.NewCipher(headerKey)
	require.NoError(t, err)
	mask := make([]byte, aes.BlockSize)
	headerBlock.Encrypt(mask, packet[numberOffset+4:numberOffset+4+aes.BlockSize])
	packet[0] ^= mask[0] & 0x0f
	packet[numberOffset] ^= mask[1]
	return packet
}

// initialFlood delivers on every read, at once, the next QUIC Initial of a ClientHello that
// never completes.
type initialFlood struct {
	N.PacketConn
	t     *testing.T
	reads int
}

func (c *initialFlood) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	const fragment = 1000
	buffer.Write(quicInitial(c.t, uint64(c.reads*fragment), make([]byte, fragment)))
	c.reads++
	return M.ParseSocksaddr("192.0.2.1:443"), nil
}

func (c *initialFlood) SetReadDeadline(time.Time) error { return nil }

func (c *initialFlood) LocalAddr() net.Addr { return &net.UDPAddr{} }

// A client whose QUIC Initials never complete a ClientHello does not keep the sniff reading
// and holding its packets: it ends after maxSniffPackets, with an error that later sniffs
// do not resume from.
func TestSniffPacketsBounded(t *testing.T) {
	router := &Router{logger: log.NewNOPFactory().NewLogger("router")}
	conn := &initialFlood{t: t}
	action := &R.RuleActionSniff{PacketSniffers: []sniff.PacketSniffer{sniff.QUICClientHello}}
	var metadata adapter.InboundContext
	_, packetBuffers, fatalErr := router.actionSniff(context.Background(), &metadata, action, nil, conn, nil, nil)
	require.NoError(t, fatalErr)
	require.Len(t, packetBuffers, maxSniffPackets)
	require.Equal(t, maxSniffPackets, conn.reads)
	require.Error(t, metadata.SniffError)
	require.NotErrorIs(t, metadata.SniffError, sniff.ErrNeedMoreData)
	N.ReleaseMultiPacketBuffer(packetBuffers)
}

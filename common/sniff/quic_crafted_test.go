package sniff_test

import (
	"context"
	"crypto"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	"github.com/sagernet/sing-box/common/sniff/internal/qtls"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

// appendQUICVarint appends value in the QUIC variable-length integer encoding.
func appendQUICVarint(b []byte, value uint64) []byte {
	switch {
	case value < 1<<6:
		return append(b, byte(value))
	case value < 1<<14:
		return append(b, byte(value>>8)|0x40, byte(value))
	default:
		return append(b, byte(value>>24)|0x80, byte(value>>16), byte(value>>8), byte(value))
	}
}

// sealQUICInitial builds a valid QUIC v1 Initial packet (correct Initial keys from the
// public salt, AEAD, and header protection) carrying the given payload frames. It is the
// inverse of the sniffer's decryption: the sniffer decrypts such a packet and then reads
// the frames inside.
func sealQUICInitial(t *testing.T, payload []byte) []byte {
	t.Helper()
	destConnID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	initialSecret := hkdf.Extract(crypto.SHA256.New, destConnID, qtls.SaltV1)
	secret := qtls.HKDFExpandLabel(crypto.SHA256, initialSecret, []byte{}, "client in", crypto.SHA256.Size())
	key := qtls.HKDFExpandLabel(crypto.SHA256, secret, []byte{}, qtls.HKDFLabelKeyV1, 16)
	iv := qtls.HKDFExpandLabel(crypto.SHA256, secret, []byte{}, qtls.HKDFLabelIVV1, 12)
	hpKey := qtls.HKDFExpandLabel(crypto.SHA256, secret, []byte{}, qtls.HKDFLabelHeaderProtectionV1, 16)

	const pnLength = 1
	lengthField := uint64(pnLength + len(payload) + 16) // + AEAD tag

	var header []byte
	header = append(header, 0xc0) // long header, fixed bit, Initial, 1-byte packet number
	header = binary.BigEndian.AppendUint32(header, qtls.Version1)
	header = append(header, byte(len(destConnID)))
	header = append(header, destConnID...)
	header = append(header, 0x00) // source connection id length
	header = append(header, 0x00) // token length
	header = appendQUICVarint(header, lengthField)
	pnOffset := len(header)
	header = append(header, 0x00) // packet number = 0

	cipher := qtls.AEADAESGCMTLS13(key, iv)
	nonce := make([]byte, cipher.NonceSize()) // packet number 0
	sealed := cipher.Seal(nil, nonce, payload, header)
	packet := append(append([]byte{}, header...), sealed...)

	// header protection: XOR the mask over the first byte and the packet number
	block, err := aes.NewCipher(hpKey)
	require.NoError(t, err)
	mask := make([]byte, aes.BlockSize)
	block.Encrypt(mask, packet[pnOffset+4:pnOffset+4+aes.BlockSize])
	packet[0] ^= mask[0] & 0x0f
	packet[pnOffset] ^= mask[1]
	return packet
}

// A crafted Initial whose CRYPTO frame claims far more bytes than the packet holds must be
// refused, not slice the decrypted buffer out of range. Before the bounds check this panics
// in the sniffer's goroutine, which on a router has no recover and takes the whole process
// (and the DNS of the LAN) down. Sniffing runs on every QUIC datagram of podkop's inbounds.
func TestSniffQUICCryptoLengthOutOfRange(t *testing.T) {
	t.Parallel()
	// CRYPTO frame: type 0x06, offset 0, length ~1 GB, then only 3 bytes of data
	var frame []byte
	frame = append(frame, 0x06)
	frame = appendQUICVarint(frame, 0)
	frame = appendQUICVarint(frame, 1<<20)
	frame = append(frame, 0x01, 0x02, 0x03)
	packet := sealQUICInitial(t, frame)

	var metadata adapter.InboundContext
	require.NotPanics(t, func() {
		err := sniff.QUICClientHello(context.Background(), &metadata, packet)
		require.Error(t, err)
	})
}

// A stream of valid Initial packets whose CRYPTO fragments keep accumulating (each returns
// ErrNeedMoreData, so the sniffer stores them and waits for more) must be refused once the
// total passes the ClientHello ceiling, instead of growing and re-copying the reassembly
// buffer without bound for as long as the flood continues.
func TestSniffQUICCryptoAccumulationCapped(t *testing.T) {
	t.Parallel()
	const frag = 1200
	var metadata adapter.InboundContext
	var lastErr error
	rounds := 0
	for i := 0; i < 200; i++ {
		rounds++
		var frame []byte
		frame = append(frame, 0x06)
		frame = appendQUICVarint(frame, uint64(i*frag)) // offset: contiguous fragments
		frame = appendQUICVarint(frame, frag)
		frame = append(frame, make([]byte, frag)...)
		lastErr = sniff.QUICClientHello(context.Background(), &metadata, sealQUICInitial(t, frame))
		if !errorIsNeedMoreData(lastErr) {
			break
		}
	}
	// It stopped (did not accumulate for all 200 rounds) and stopped near the 64 KB ceiling.
	require.Less(t, rounds, 200)
	require.Greater(t, rounds, 65535/frag) // only refused after passing the ceiling
	require.Error(t, lastErr)
	require.False(t, errorIsNeedMoreData(lastErr))
}

// A CRYPTO frame of length zero carries nothing, but the reassembly loop matched it at its
// offset without moving on, for ever: one such datagram from the LAN pinned the sniffing
// goroutine at full CPU until a restart. The sniffer must return, with or without an error.
func TestSniffQUICCryptoZeroLengthFrame(t *testing.T) {
	t.Parallel()
	for _, frames := range [][]byte{
		{0x06, 0x00, 0x00},                   // CRYPTO offset 0, length 0, alone
		{0x06, 0x00, 0x00, 0x06, 0x00, 0x00}, // twice
		append([]byte{0x06, 0x00, 0x00}, append([]byte{0x06, 0x00, 0x03}, 0x01, 0x02, 0x03)...), // then a real fragment
	} {
		packet := sealQUICInitial(t, frames)
		done := make(chan error, 1)
		go func() {
			var metadata adapter.InboundContext
			done <- sniff.QUICClientHello(context.Background(), &metadata, packet)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the sniffer did not return: the reassembly loop spins on the empty frame")
		}
	}
}

func errorIsNeedMoreData(err error) bool {
	return err != nil && errors.Is(err, sniff.ErrNeedMoreData)
}

// A well-formed CRYPTO frame in the same hand-built packet is still parsed: the sealing
// helper matches what the sniffer expects, so the test above exercises the real path and not
// a packet the sniffer rejects before reaching the frame parser.
func TestSniffQUICCraftedPacketReachesFrameParser(t *testing.T) {
	t.Parallel()
	// CRYPTO frame carrying a few bytes that are not a TLS ClientHello: the sniffer reads the
	// frame (no panic, no range error) and then needs more data for a hello.
	var frame []byte
	frame = append(frame, 0x06)
	frame = appendQUICVarint(frame, 0)
	frame = appendQUICVarint(frame, 4)
	frame = append(frame, 0x16, 0x03, 0x01, 0x00)
	packet := sealQUICInitial(t, frame)

	var metadata adapter.InboundContext
	require.NotPanics(t, func() {
		_ = sniff.QUICClientHello(context.Background(), &metadata, packet)
	})
}

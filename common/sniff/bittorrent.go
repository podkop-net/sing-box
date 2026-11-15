package sniff

import (
	"context"
	"encoding/binary"
	"io"
	"os"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	trackerConnectFlag    = 0
	trackerProtocolID     = 0x41727101980
	trackerConnectMinSize = 16
)

// BitTorrent detects if the stream is a BitTorrent connection.
// For the BitTorrent protocol specification, see https://www.bittorrent.org/beps/bep_0003.html
func BitTorrent(_ context.Context, metadata *adapter.InboundContext, reader io.Reader) error {
	var first byte
	err := binary.Read(reader, binary.BigEndian, &first)
	if err != nil {
		return E.Cause1(ErrNeedMoreData, err)
	}

	if first != 19 {
		return os.ErrInvalid
	}

	const header = "BitTorrent protocol"
	var protocol [19]byte
	var n int
	n, err = reader.Read(protocol[:])
	if string(protocol[:n]) != header[:n] {
		return os.ErrInvalid
	}
	if err != nil {
		return E.Cause1(ErrNeedMoreData, err)
	}
	if n < 19 {
		return ErrNeedMoreData
	}

	metadata.Protocol = C.ProtocolBitTorrent
	return nil
}

// UTP detects if the packet is a uTP connection packet.
// For the uTP protocol specification, see
//  1. https://www.bittorrent.org/beps/bep_0029.html
//  2. https://github.com/bittorrent/libutp/blob/2b364cbb0650bdab64a5de2abb4518f9f228ec44/utp_internal.cpp#L112
//
// podkop-engine: only the start of a connection, as Xray tells it: a SYN of version 1 (0x41), with
// a timestamp difference of 0 (nothing came from the peer yet) and extensions that end exactly at
// the end of the packet (a SYN carries no data). A data packet cannot be told from one packet: a
// plain WireGuard handshake initiation (148 bytes, the type 1 as four little-endian bytes) reads
// as one without extensions, and began every WireGuard tunnel taken for BitTorrent; one random
// packet in about 6,400 did too. The UDP socket of a client starts with a DHT message (DHT).
func UTP(_ context.Context, metadata *adapter.InboundContext, packet []byte) error {
	// A valid uTP packet must be at least 20 bytes long.
	if len(packet) < 20 {
		return os.ErrInvalid
	}
	if packet[0] != utpSYN {
		return os.ErrInvalid
	}
	if binary.BigEndian.Uint32(packet[8:12]) != 0 {
		return os.ErrInvalid
	}
	end, valid := utpExtensionsEnd(packet)
	if !valid || end != len(packet) {
		return os.ErrInvalid
	}
	metadata.Protocol = C.ProtocolBitTorrent
	return nil
}

// utpSYN is the first byte of a SYN of uTP version 1: the type ST_SYN (4) and the version.
const utpSYN = 4<<4 | 1

// utpExtensionsEnd follows the extensions of a uTP packet, from the type in its header, and returns
// where they end: at most four, of the types BEP 29 and libutp know, a selective ACK (1: a
// bitmask, a multiple of 4 bytes) and the extension bits (2: 8 bytes).
func utpExtensionsEnd(packet []byte) (int, bool) {
	kind := packet[1]
	offset := 20
	for count := 0; kind != 0; count++ {
		if count == 4 || offset+2 > len(packet) {
			return 0, false
		}
		next, length := packet[offset], int(packet[offset+1])
		switch kind {
		case 1:
			if length < 4 || length%4 != 0 {
				return 0, false
			}
		case 2:
			if length != 8 {
				return 0, false
			}
		default:
			return 0, false
		}
		offset += 2 + length
		if offset > len(packet) {
			return 0, false
		}
		kind = next
	}
	return offset, true
}

// UDPTracker detects if the packet is a UDP Tracker Protocol packet.
// For the UDP Tracker Protocol specification, see https://www.bittorrent.org/beps/bep_0015.html
func UDPTracker(_ context.Context, metadata *adapter.InboundContext, packet []byte) error {
	if len(packet) < trackerConnectMinSize {
		return os.ErrInvalid
	}
	if binary.BigEndian.Uint64(packet[:8]) != trackerProtocolID {
		return os.ErrInvalid
	}
	if binary.BigEndian.Uint32(packet[8:12]) != trackerConnectFlag {
		return os.ErrInvalid
	}
	metadata.Protocol = C.ProtocolBitTorrent
	return nil
}

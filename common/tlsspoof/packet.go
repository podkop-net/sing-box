//go:build linux || darwin || (windows && (amd64 || 386))

package tlsspoof

import (
	"encoding/binary"
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
)

// The forged segment is encoded here, not with the packet headers of sing-tun as in
// sing-box 1.14: that package is internal in the sing-tun of this line. The packets are
// the same byte for byte (TestSpoofFrameVectors).

const (
	defaultTTL        uint8  = 64
	defaultWindowSize uint16 = 0xFFFF

	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
	tcpHeaderLen  = 20

	ipProtocolTCP = 6
	tcpFlagPsh    = 0x08
	tcpFlagAck    = 0x10

	tcpOptionEOL                = 0
	tcpOptionNOP                = 1
	tcpOptionTimestamp          = 8
	tcpOptionTimestampLength    = 10
	tcpOptionMD5Signature       = 19
	tcpOptionMD5SignatureLength = 18
	tcpTimestampBackdate        = 3600000
)

type spoofPacketInfo struct {
	seqNum  uint32
	ackNum  uint32
	corrupt bool
	options []byte
}

func buildTCPSegment(
	src netip.AddrPort,
	dst netip.AddrPort,
	packetInfo spoofPacketInfo,
	payload []byte,
) []byte {
	if src.Addr().Is4() != dst.Addr().Is4() {
		panic("tlsspoof: mixed IPv4/IPv6 address family")
	}
	var (
		frame       []byte
		ipHeaderLen int
	)
	ipPayloadLen := tcpHeaderLen + len(packetInfo.options) + len(payload)
	if src.Addr().Is4() {
		ipHeaderLen = ipv4HeaderLen
		frame = make([]byte, ipHeaderLen+ipPayloadLen)
		ip := frame[:ipHeaderLen]
		ip[0] = 4<<4 | ipv4HeaderLen/4
		binary.BigEndian.PutUint16(ip[2:], uint16(len(frame)))
		ip[8] = defaultTTL
		ip[9] = ipProtocolTCP
		copy(ip[12:16], src.Addr().AsSlice())
		copy(ip[16:20], dst.Addr().AsSlice())
		binary.BigEndian.PutUint16(ip[10:], foldChecksum(sumWords(0, ip)))
	} else {
		ipHeaderLen = ipv6HeaderLen
		frame = make([]byte, ipHeaderLen+ipPayloadLen)
		ip := frame[:ipHeaderLen]
		ip[0] = 6 << 4
		binary.BigEndian.PutUint16(ip[4:], uint16(ipPayloadLen))
		ip[6] = ipProtocolTCP
		ip[7] = defaultTTL
		copy(ip[8:24], src.Addr().AsSlice())
		copy(ip[24:40], dst.Addr().AsSlice())
	}
	encodeTCP(frame, ipHeaderLen, src, dst, packetInfo, payload)
	return frame
}

func encodeTCP(frame []byte, ipHeaderLen int, src, dst netip.AddrPort, packetInfo spoofPacketInfo, payload []byte) {
	tcp := frame[ipHeaderLen:]
	copy(tcp[tcpHeaderLen:], packetInfo.options)
	optionsLen := len(packetInfo.options)
	copy(tcp[tcpHeaderLen+optionsLen:], payload)
	binary.BigEndian.PutUint16(tcp[0:], src.Port())
	binary.BigEndian.PutUint16(tcp[2:], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:], packetInfo.seqNum)
	binary.BigEndian.PutUint32(tcp[8:], packetInfo.ackNum)
	tcp[12] = uint8((tcpHeaderLen+optionsLen)/4) << 4
	tcp[13] = tcpFlagAck | tcpFlagPsh
	binary.BigEndian.PutUint16(tcp[14:], defaultWindowSize)
	applyTCPChecksum(tcp, src.Addr(), dst.Addr(), packetInfo.corrupt)
}

func buildSpoofFrame(method Method, src, dst netip.AddrPort, sendNext, receiveNext, timestamp uint32, tcpOptions, payload []byte) ([]byte, error) {
	packetInfo, err := resolveSpoofPacketInfo(method, sendNext, receiveNext, timestamp, tcpOptions, payload)
	if err != nil {
		return nil, err
	}
	return buildTCPSegment(src, dst, packetInfo, payload), nil
}

func resolveSpoofPacketInfo(method Method, sendNext, receiveNext, timestamp uint32, tcpOptions, payload []byte) (spoofPacketInfo, error) {
	packetInfo := spoofPacketInfo{seqNum: sendNext, ackNum: receiveNext}
	switch method {
	case MethodWrongSequence:
		packetInfo.seqNum = sendNext - uint32(len(payload))
	case MethodWrongChecksum:
		packetInfo.corrupt = true
	case MethodWrongAcknowledgment:
		packetInfo.ackNum = receiveNext - uint32(defaultWindowSize/2)
	case MethodWrongMD5Sig:
		packetInfo.options = buildMD5SignatureOptions()
	case MethodWrongTimestamp:
		packetInfo.options = buildWrongTimestampOptions(timestamp, tcpOptions)
	default:
		return packetInfo, E.New("tls_spoof: unknown method ", method)
	}
	return packetInfo, nil
}

func buildMD5SignatureOptions() []byte {
	options := make([]byte, tcpOptionMD5SignatureLength+2)
	options[0] = tcpOptionMD5Signature
	options[1] = tcpOptionMD5SignatureLength
	return options
}

func buildWrongTimestampOptions(timestamp uint32, tcpOptions []byte) []byte {
	spoofedTimestamp := timestamp
	if spoofedTimestamp > tcpTimestampBackdate {
		spoofedTimestamp -= tcpTimestampBackdate
	} else {
		spoofedTimestamp = 0
	}
	if rewriteTCPOptionTimestamp(tcpOptions, spoofedTimestamp) {
		return tcpOptions
	}
	options := make([]byte, tcpOptionTimestampLength+2)
	options[0] = tcpOptionTimestamp
	options[1] = tcpOptionTimestampLength
	binary.BigEndian.PutUint32(options[2:], spoofedTimestamp)
	return options
}

// rewriteTCPOptionTimestamp finds the TS option in tcpOptions and writes
// timestamp into its TSVal field in place. The caller must own tcpOptions.
func rewriteTCPOptionTimestamp(tcpOptions []byte, timestamp uint32) bool {
	for i := 0; i < len(tcpOptions); {
		switch tcpOptions[i] {
		case tcpOptionEOL:
			return false
		case tcpOptionNOP:
			i++
			continue
		}
		if i+1 >= len(tcpOptions) {
			return false
		}
		optionLen := int(tcpOptions[i+1])
		if optionLen < 2 || i+optionLen > len(tcpOptions) {
			return false
		}
		if tcpOptions[i] == tcpOptionTimestamp && optionLen == tcpOptionTimestampLength {
			binary.BigEndian.PutUint32(tcpOptions[i+2:], timestamp)
			return true
		}
		i += optionLen
	}
	return false
}

// applyTCPChecksum writes the checksum of the segment tcp (header, options and payload,
// the checksum field still zero) over the pseudo header of its addresses.
func applyTCPChecksum(tcp []byte, srcAddr, dstAddr netip.Addr, corrupt bool) {
	sum := sumWords(0, srcAddr.AsSlice())
	sum = sumWords(sum, dstAddr.AsSlice())
	sum += ipProtocolTCP
	sum += uint32(len(tcp))
	tcpChecksum := foldChecksum(sumWords(sum, tcp))
	if corrupt {
		tcpChecksum ^= 0xFFFF
	}
	binary.BigEndian.PutUint16(tcp[16:], tcpChecksum)
}

// sumWords adds the 16-bit big-endian words of data to sum; an odd last byte counts as
// the high byte of a word.
func sumWords(sum uint32, data []byte) uint32 {
	for len(data) >= 2 {
		sum += uint32(data[0])<<8 | uint32(data[1])
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	return sum
}

func foldChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	return ^uint16(sum)
}

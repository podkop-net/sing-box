package sniff_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

func TestSniffDNS(t *testing.T) {
	t.Parallel()
	query, err := hex.DecodeString("740701000001000000000000012a06676f6f676c6503636f6d0000010001")
	require.NoError(t, err)
	var metadata adapter.InboundContext
	err = sniff.DomainNameQuery(context.TODO(), &metadata, query)
	require.NoError(t, err)
	require.Equal(t, C.ProtocolDNS, metadata.Protocol)
}

func TestSniffStreamDNS(t *testing.T) {
	t.Parallel()
	query, err := hex.DecodeString("001e740701000001000000000000012a06676f6f676c6503636f6d0000010001")
	require.NoError(t, err)
	var metadata adapter.InboundContext
	err = sniff.StreamDomainNameQuery(context.TODO(), &metadata, bytes.NewReader(query))
	require.NoError(t, err)
	require.Equal(t, C.ProtocolDNS, metadata.Protocol)
}

func TestSniffIncompleteStreamDNS(t *testing.T) {
	t.Parallel()
	query, err := hex.DecodeString("001e740701000001000000000000")
	require.NoError(t, err)
	var metadata adapter.InboundContext
	err = sniff.StreamDomainNameQuery(context.TODO(), &metadata, bytes.NewReader(query))
	require.ErrorIs(t, err, sniff.ErrNeedMoreData)
}

func TestSniffNotStreamDNS(t *testing.T) {
	t.Parallel()
	query, err := hex.DecodeString("001e740701000000000000000000")
	require.NoError(t, err)
	var metadata adapter.InboundContext
	err = sniff.StreamDomainNameQuery(context.TODO(), &metadata, bytes.NewReader(query))
	require.NotEmpty(t, err)
	require.NotErrorIs(t, err, sniff.ErrNeedMoreData)
}

const (
	testDNSQuery    = "740701000001000000000000012a06676f6f676c6503636f6d0000010001"
	testDNSResponse = "740781800001000100000000012a06676f6f676c6503636f6d0000010001c00c000100010000012c00047f000001"
	// the packets of TestSniffNTP and TestSniffDTLSClientHello: both unpack as a DNS
	// message without a question
	testNTPRequest = "1b0006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	testDTLSHello  = "16fefd0000000000000000007e010000720000000000000072fefd668a43523798e064bd806d0c87660de9c611a59bbdfc3892c4e072d94f2cafc40000000cc02bc02fc00ac014c02cc0300100003c000d0010000e0403050306030401050106010807ff01000100000a00080006001d00170018000b00020100000e000900060008000700010000170000"
)

// A datagram that unpacks as a DNS message but is no query is an error of this sniffer.
func TestSniffDNSNotQuery(t *testing.T) {
	t.Parallel()
	for name, packetHex := range map[string]string{
		"response":    testDNSResponse,
		"no question": "740701000000000000000000",
		"ntp request": testNTPRequest,
		"dtls record": testDTLSHello,
	} {
		packet, err := hex.DecodeString(packetHex)
		require.NoError(t, err, name)
		var metadata adapter.InboundContext
		err = sniff.DomainNameQuery(context.TODO(), &metadata, packet)
		require.Error(t, err, name)
		require.Empty(t, metadata.Protocol, name)
	}
}

// The sniffers of a packet in the order the router has them by default: what the DNS
// sniffer does not take reaches the ones after it.
func TestSniffPacketAfterDNS(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, packet, protocol string }{
		{"dns query", testDNSQuery, C.ProtocolDNS},
		{"ntp request", testNTPRequest, C.ProtocolNTP},
		{"dtls record", testDTLSHello, C.ProtocolDTLS},
	} {
		packet, err := hex.DecodeString(test.packet)
		require.NoError(t, err, test.name)
		var metadata adapter.InboundContext
		err = sniff.PeekPacket(context.TODO(), &metadata, packet,
			sniff.DomainNameQuery, sniff.QUICClientHello, sniff.STUNMessage, sniff.UTP, sniff.UDPTracker, sniff.DTLSRecord, sniff.NTP)
		require.NoError(t, err, test.name)
		require.Equal(t, test.protocol, metadata.Protocol, test.name)
	}
	response, err := hex.DecodeString(testDNSResponse)
	require.NoError(t, err)
	var metadata adapter.InboundContext
	err = sniff.PeekPacket(context.TODO(), &metadata, response,
		sniff.DomainNameQuery, sniff.QUICClientHello, sniff.STUNMessage, sniff.UTP, sniff.UDPTracker, sniff.DTLSRecord, sniff.NTP)
	require.Error(t, err, "a DNS response is no protocol of any sniffer")
	require.Empty(t, metadata.Protocol)
}

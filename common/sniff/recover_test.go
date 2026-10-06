package sniff

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"

	"github.com/stretchr/testify/require"
)

func panickingStreamSniffer(_ context.Context, metadata *adapter.InboundContext, _ io.Reader) error {
	metadata.Protocol = C.ProtocolTLS
	metadata.Domain = "half.example"
	var empty []byte
	_ = empty[1]
	return nil
}

func panickingPacketSniffer(_ context.Context, metadata *adapter.InboundContext, packet []byte) error {
	metadata.Protocol = C.ProtocolQUIC
	metadata.SniffContext = "half"
	return panickingStreamSniffer(context.Background(), metadata, bytes.NewReader(packet))
}

// A sniffer that panics fails the sniff of its connection, with the panic in one line and
// its stack apart, and leaves the metadata as it found it; the next sniffer still runs.
func TestSnifferPanicRecovered(t *testing.T) {
	var metadata adapter.InboundContext
	err := PeekPacket(context.Background(), &metadata, []byte("packet"), panickingPacketSniffer)
	require.ErrorIs(t, err, ErrSnifferPanicked)
	require.Equal(t, "sniffer panicked: runtime error: index out of range [1] with length 0", err.Error())
	var panicError *SnifferPanicError
	require.ErrorAs(t, err, &panicError)
	require.Contains(t, string(panicError.Stack), "panickingStreamSniffer")
	require.Empty(t, metadata.Protocol)
	require.Empty(t, metadata.Domain)
	require.Nil(t, metadata.SniffContext)

	err = PeekPacket(context.Background(), &metadata, []byte("packet"), panickingPacketSniffer,
		func(_ context.Context, metadata *adapter.InboundContext, _ []byte) error {
			metadata.Protocol = C.ProtocolDNS
			return nil
		})
	require.NoError(t, err)
	require.Equal(t, C.ProtocolDNS, metadata.Protocol)

	// among the failures of other sniffers the panic and its stack are still found
	metadata = adapter.InboundContext{}
	err = PeekPacket(context.Background(), &metadata, []byte("packet"),
		func(context.Context, *adapter.InboundContext, []byte) error { return os.ErrInvalid },
		panickingPacketSniffer)
	require.ErrorIs(t, err, os.ErrInvalid)
	require.ErrorIs(t, err, ErrSnifferPanicked)
	panicError = nil
	require.ErrorAs(t, err, &panicError)
	require.NotEmpty(t, panicError.Stack)
	require.NotContains(t, err.Error(), "\n")

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go server.Write([]byte("stream"))
	metadata = adapter.InboundContext{}
	buffer := buf.NewPacket()
	defer buffer.Release()
	err = PeekStream(context.Background(), &metadata, client, nil, buffer, 0, panickingStreamSniffer)
	require.True(t, errors.Is(err, ErrSnifferPanicked))
	require.Empty(t, metadata.Protocol)
	require.Empty(t, metadata.Domain)
}

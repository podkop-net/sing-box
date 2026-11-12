package sniff

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

type (
	StreamSniffer = func(ctx context.Context, metadata *adapter.InboundContext, reader io.Reader) error
	PacketSniffer = func(ctx context.Context, metadata *adapter.InboundContext, packet []byte) error
)

var ErrNeedMoreData = E.New("need more data")

// ErrSnifferPanicked is the failure of a sniffer that panicked. Sniffers parse what any
// client sends: a panic, a bug on input the sniffer did not expect, costs the sniff of one
// connection instead of the process.
var ErrSnifferPanicked = E.New("sniffer panicked")

// SnifferPanicError is what a sniffer that panicked returns; errors.Is finds
// ErrSnifferPanicked in it. Its text is one line: it stays in the metadata of the
// connection, which trackers keep, and such connections can come by the hundred. The stack
// is apart, for whoever logs the bug.
type SnifferPanicError struct {
	Value string // the panic
	Stack []byte
}

func (e *SnifferPanicError) Error() string {
	return ErrSnifferPanicked.Error() + ": " + e.Value
}

func (e *SnifferPanicError) Unwrap() error {
	return ErrSnifferPanicked
}

// recovered runs a sniffer. On a panic it restores the metadata the sniffer may have set
// and returns a SnifferPanicError with the panic and its stack.
func recovered(metadata *adapter.InboundContext, sniff func() error) (err error) {
	protocol, domain, client, sniffContext := metadata.Protocol, metadata.Domain, metadata.Client, metadata.SniffContext
	defer func() {
		if panicked := recover(); panicked != nil {
			metadata.Protocol, metadata.Domain, metadata.Client, metadata.SniffContext = protocol, domain, client, sniffContext
			err = &SnifferPanicError{Value: fmt.Sprint(panicked), Stack: debug.Stack()}
		}
	}()
	return sniff()
}

func Skip(metadata *adapter.InboundContext) bool {
	// skip server first protocols
	switch metadata.Destination.Port {
	case 25, 465, 587:
		// SMTP
		return true
	case 143, 993:
		// IMAP
		return true
	case 110, 995:
		// POP3
		return true
	}
	return false
}

func PeekStream(ctx context.Context, metadata *adapter.InboundContext, conn net.Conn, buffers []*buf.Buffer, buffer *buf.Buffer, timeout time.Duration, sniffers ...StreamSniffer) error {
	if timeout == 0 {
		timeout = C.ReadPayloadTimeout
	}
	deadline := time.Now().Add(timeout)
	var sniffError error
	for i := 0; ; i++ {
		err := conn.SetReadDeadline(deadline)
		if err != nil {
			return E.Cause(err, "set read deadline")
		}
		_, err = buffer.ReadOnceFrom(conn)
		_ = conn.SetReadDeadline(time.Time{})
		if err != nil {
			if i > 0 {
				break
			}
			return E.Cause(err, "read payload")
		}
		sniffError = nil
		for _, sniffer := range sniffers {
			reader := io.MultiReader(common.Map(append(buffers, buffer), func(it *buf.Buffer) io.Reader {
				return bytes.NewReader(it.Bytes())
			})...)
			err = recovered(metadata, func() error { return sniffer(ctx, metadata, reader) })
			if err == nil {
				return nil
			}
			sniffError = E.Errors(sniffError, err)
		}
		if !errors.Is(sniffError, ErrNeedMoreData) {
			break
		}
	}
	return sniffError
}

func PeekPacket(ctx context.Context, metadata *adapter.InboundContext, packet []byte, sniffers ...PacketSniffer) error {
	var sniffError []error
	for _, sniffer := range sniffers {
		err := recovered(metadata, func() error { return sniffer(ctx, metadata, packet) })
		if err == nil {
			return nil
		}
		sniffError = append(sniffError, err)
	}
	return E.Errors(sniffError...)
}

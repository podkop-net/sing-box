package route

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

type levelLogger struct {
	logger.ContextLogger
	debug, errors int
}

func (l *levelLogger) DebugContext(context.Context, ...any) { l.debug++ }
func (l *levelLogger) ErrorContext(context.Context, ...any) { l.errors++ }

type typedOutbound struct {
	outbound.Adapter
}

func (o *typedOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, os.ErrInvalid
}

func (o *typedOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

// A connection a block outbound refused is logged at debug, as one the reject action refused;
// another that could not be opened stays an error.
func TestLogDialError(t *testing.T) {
	logged := &levelLogger{}
	manager := &ConnectionManager{logger: logged}
	manager.logDialError(context.Background(), &typedOutbound{Adapter: outbound.NewAdapter(C.TypeBlock, "block-out", nil, nil)}, os.ErrPermission)
	require.Equal(t, 1, logged.debug)
	require.Zero(t, logged.errors)
	manager.logDialError(context.Background(), &typedOutbound{Adapter: outbound.NewAdapter(C.TypeVLESS, "server", nil, nil)}, os.ErrDeadlineExceeded)
	require.Equal(t, 1, logged.errors)
}

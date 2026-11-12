package route

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
)

// logDialError logs a connection that could not be opened. One a block outbound refused was
// refused on purpose, as the reject action refuses (logged at debug there): a section of
// podkop whose group has no server goes to a block outbound, and an error line a connection
// would flood the log (podkop-engine).
func (m *ConnectionManager) logDialError(ctx context.Context, this N.Dialer, err error) {
	if outbound, isOutbound := this.(adapter.Outbound); isOutbound && outbound.Type() == C.TypeBlock {
		m.logger.DebugContext(ctx, err)
		return
	}
	m.logger.ErrorContext(ctx, err)
}

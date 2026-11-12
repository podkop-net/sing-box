package route

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

// inboundLoopError refuses a connection the direct outbound would dial back to the inbound
// it came in on, see wouldLoopToInbound.
type inboundLoopError struct {
	inbound string
	error
}

func (e *inboundLoopError) Unwrap() error {
	return e.error
}

// Such refusals are logged here, by inbound. What reaches the listen address of an inbound
// without being hijacked usually keeps coming, and every datagram is a session of its own:
// the first refusal is logged at once, and while they go on, one line every
// loopRefusalLogInterval counts the refusals in between and shows the last one.
var loopRefusalLogInterval = 10 * time.Second

type loopRefusalLog struct {
	access  sync.Mutex
	windows map[string]*loopRefusalWindow
}

type loopRefusalWindow struct {
	count int
	last  error
}

func (l *loopRefusalLog) refused(ctx context.Context, logger log.ContextLogger, refusal *inboundLoopError) {
	inbound := refusal.inbound
	l.access.Lock()
	if l.windows == nil {
		l.windows = make(map[string]*loopRefusalWindow)
	}
	window, open := l.windows[inbound]
	if open {
		window.count++
		window.last = refusal
		l.access.Unlock()
		return
	}
	l.windows[inbound] = &loopRefusalWindow{}
	l.access.Unlock()
	logger.ErrorContext(ctx, refusal)
	time.AfterFunc(loopRefusalLogInterval, func() { l.flush(logger, inbound) })
}

func (l *loopRefusalLog) flush(logger log.ContextLogger, inbound string) {
	l.access.Lock()
	window := l.windows[inbound]
	if window.count == 0 {
		delete(l.windows, inbound)
		l.access.Unlock()
		return
	}
	count, last := window.count, window.last
	window.count = 0
	l.access.Unlock()
	logger.Error(E.Cause(last, "inbound ", inbound, ": ", count, " more refused in ", loopRefusalLogInterval, ", the last"))
	time.AfterFunc(loopRefusalLogInterval, func() { l.flush(logger, inbound) })
}

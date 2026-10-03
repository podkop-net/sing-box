package dns

import (
	"context"
	"errors"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"

	"github.com/miekg/dns"
)

// Failed exchanges are logged here, by server (podkop-engine). The first failure of a
// server is logged at once with its query; while the server goes on failing, one line
// every failureLogInterval counts the failures in between and shows the last one. A
// timeout is a failure; a query its caller gave up (context.Canceled) is not. Upstream
// logged nothing for most failures (the rule path of 1.14, and timeouts or closed
// connections on the path of clients) or one line per query, which floods the log of
// a router when a server is down.
var failureLogInterval = 10 * time.Second

type failureLog struct {
	access  sync.Mutex
	windows map[string]*failureWindow
}

type failureWindow struct {
	count    int
	question string
	err      error
}

// loggedFailure marks an error that the failure log has taken: callers do not log it
// again.
type loggedFailure struct {
	error
}

func (e *loggedFailure) Unwrap() error {
	return e.error
}

// IsLoggedFailure tells whether the failure log has taken the error.
func IsLoggedFailure(err error) bool {
	var logged *loggedFailure
	return errors.As(err, &logged)
}

func (l *failureLog) failed(ctx context.Context, logger logger.ContextLogger, server string, message *dns.Msg, err error) error {
	if logger == nil || errors.Is(err, context.Canceled) || IsLoggedFailure(err) {
		return err
	}
	question := "<empty query>"
	if len(message.Question) > 0 {
		question = FormatQuestion(message.Question[0].String())
	}
	l.access.Lock()
	if l.windows == nil {
		l.windows = make(map[string]*failureWindow)
	}
	window, open := l.windows[server]
	if open {
		window.count++
		window.question, window.err = question, err
		l.access.Unlock()
		return &loggedFailure{err}
	}
	l.windows[server] = &failureWindow{}
	l.access.Unlock()
	logger.ErrorContext(ctx, E.Cause(err, "server ", server, ": exchange failed for ", question))
	time.AfterFunc(failureLogInterval, func() { l.flush(logger, server) })
	return &loggedFailure{err}
}

func (l *failureLog) flush(logger logger.ContextLogger, server string) {
	l.access.Lock()
	window := l.windows[server]
	if window.count == 0 {
		delete(l.windows, server)
		l.access.Unlock()
		return
	}
	count, question, err := window.count, window.question, window.err
	window.count = 0
	l.access.Unlock()
	logger.Error(E.Cause(err, "server ", server, ": ", count, " more exchanges failed in ", failureLogInterval, ", the last for ", question))
	time.AfterFunc(failureLogInterval, func() { l.flush(logger, server) })
}

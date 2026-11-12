package rule

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

type levelLog struct {
	access sync.Mutex
	lines  []string
}

func (l *levelLog) WriteMessage(level log.Level, message string) {
	l.access.Lock()
	defer l.access.Unlock()
	name := map[log.Level]string{log.LevelError: "ERROR", log.LevelInfo: "INFO", log.LevelDebug: "DEBUG"}[level]
	l.lines = append(l.lines, name+" "+message)
}

func (l *levelLog) take() []string {
	l.access.Lock()
	defer l.access.Unlock()
	lines := l.lines
	l.lines = nil
	return lines
}

// A rule-set that keeps failing to update logs the first failure as an error, the next ones
// at debug and, every ruleSetFailureLogInterval, a count; the success after them says how
// many there were. Only an update that loaded a list reports it (the updater collects
// garbage after one), a failed or not-modified one does not.
func TestRemoteRuleSetUpdateFailuresLogged(t *testing.T) {
	var mode atomic.Value
	mode.Store("fail")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load().(string) {
		case "fail":
			w.WriteHeader(http.StatusBadGateway)
		case "list":
			w.Header().Set("Etag", `"v1"`)
			io.WriteString(w, `{"version":3,"rules":[{"domain_suffix":["example.com"]}]}`)
		case "same":
			w.WriteHeader(http.StatusNotModified)
		}
	}))
	defer server.Close()

	writer := &levelLog{}
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now()}, io.Discard, "", writer, false)
	factory.SetLevel(log.LevelDebug)
	require.NoError(t, factory.Start())
	set := newTestRuleSet(server.URL)
	set.ctx = context.Background()
	set.logger = factory.NewLogger("rule-set")
	set.options.Format = C.RuleSetFormatSource

	for range 3 {
		require.False(t, set.updateOnce())
	}
	lines := writer.take()
	require.Len(t, lines, 6) // each attempt also logs "updating rule-set" at debug
	require.Equal(t, 1, countPrefix(lines, "ERROR"))
	require.Equal(t, 5, countPrefix(lines, "DEBUG"))

	set.failureLogged = time.Now().Add(-ruleSetFailureLogInterval)
	require.False(t, set.updateOnce())
	lines = writer.take()
	require.Equal(t, 1, countPrefix(lines, "ERROR"))
	require.Contains(t, strings.Join(lines, "\n"), "4 failed attempts")

	mode.Store("list")
	require.True(t, set.updateOnce())
	require.Contains(t, strings.Join(writer.take(), "\n"), "succeeded after 4 failed attempts")
	require.Zero(t, set.failures)

	mode.Store("same")
	require.False(t, set.updateOnce())
	require.Zero(t, countPrefix(writer.take(), "ERROR"))
}

func countPrefix(lines []string, prefix string) int {
	var count int
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			count++
		}
	}
	return count
}

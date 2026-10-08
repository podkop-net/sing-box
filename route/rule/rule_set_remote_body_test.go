package rule

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func swapMaxSize(size int) func() {
	old := ruleSetMaxSize
	ruleSetMaxSize = size
	return func() { ruleSetMaxSize = old }
}

const testSourceSet = `{"version":3,"rules":[{"domain_suffix":["example.com"]}]}`

// A response that declares more than the cap is refused by its length: nothing of the body
// is read into memory.
func TestRemoteRuleSetDeclaredTooLarge(t *testing.T) {
	defer swapMaxSize(1 << 20)()
	var sent int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(2<<20))
		w.WriteHeader(http.StatusOK)
		chunk := strings.Repeat("A", 64<<10)
		for range 32 {
			n, err := w.Write([]byte(chunk))
			sent += n
			if err != nil {
				return
			}
		}
	}))
	set := newTestRuleSet(server.URL)
	set.ctx = context.Background()
	set.options.Format = C.RuleSetFormatSource
	err := set.fetch(context.Background(), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "larger than 1 MB")
	server.Close()
	require.Less(t, sent, 2<<20, "the client must stop the transfer instead of reading it")
}

// A page served with status 200 where a binary rule-set is expected is refused by its first
// bytes, and the error says what came: size, type and the first bytes, quoted.
func TestRemoteRuleSetNotBinary(t *testing.T) {
	page := "<!DOCTYPE html>\n<html><body>blocked\x1b[31m</body></html>"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, page)
	}))
	defer server.Close()
	set := newTestRuleSet(server.URL)
	set.ctx = context.Background()
	set.options.Format = C.RuleSetFormatBinary
	err := set.fetch(context.Background(), nil)
	require.Error(t, err)
	message := err.Error()
	require.Contains(t, message, "not a binary rule-set")
	require.Contains(t, message, strconv.Itoa(len(page))+" bytes")
	require.Contains(t, message, `Content-Type "text/html; charset=utf-8"`)
	require.Contains(t, message, `starts with "<!DOCTYPE html>\n"`)
	require.NotContains(t, message, "\n", "the server's bytes must not break the log line")
}

// A source rule-set that does not parse reports the same description.
func TestRemoteRuleSetSourceParseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<html>not a list</html>")
	}))
	defer server.Close()
	set := newTestRuleSet(server.URL)
	set.ctx = context.Background()
	set.options.Format = C.RuleSetFormatSource
	err := set.fetch(context.Background(), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), `read rule-set (23 bytes, Content-Type "text/html", starts with "<html>not a list")`)
}

// A list loads with a declared length and without one (chunked).
func TestRemoteRuleSetBodyLoads(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if chunked {
				w.(http.Flusher).Flush()
			}
			io.WriteString(w, testSourceSet)
		}))
		set := newTestRuleSet(server.URL)
		set.ctx = context.Background()
		set.options.Format = C.RuleSetFormatSource
		require.NoError(t, set.fetch(context.Background(), nil), "chunked=%v", chunked)
		require.Len(t, set.currentRules(), 1)
		server.Close()
	}
}

// An update cut by the shutdown is not a failed update: no error line, no failure counted.
func TestRemoteRuleSetUpdateCancelledByShutdown(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush()
		<-release
	}))
	defer server.Close()
	defer close(release)

	writer := &levelLog{}
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now()}, io.Discard, "", writer, false)
	factory.SetLevel(log.LevelDebug)
	require.NoError(t, factory.Start())
	ctx, cancel := context.WithCancel(context.Background())
	set := newTestRuleSet(server.URL)
	set.ctx = ctx
	set.logger = factory.NewLogger("rule-set")
	set.options.Format = C.RuleSetFormatSource
	time.AfterFunc(200*time.Millisecond, cancel)
	require.False(t, set.updateOnce())
	require.Zero(t, set.failures)
	require.Zero(t, countPrefix(writer.take(), "ERROR"))
}

// The download is dialed as an external connection, so that a group switching members does
// not close it together with its own connections.
func TestRemoteRuleSetFetchIsExternalConnection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, testSourceSet)
	}))
	defer server.Close()
	dialer := &recordingDialer{}
	set := newTestRuleSet(server.URL)
	set.dialer = dialer
	set.options.Format = C.RuleSetFormatSource
	require.NoError(t, set.fetch(context.Background(), nil))
	require.True(t, dialer.external)
}

type recordingDialer struct {
	testDialer
	external bool
}

func (d *recordingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.external = interrupt.IsExternalConnectionFromContext(ctx)
	return d.testDialer.DialContext(ctx, network, destination)
}

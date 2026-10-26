package rule

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
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
	// far more than the socket buffers of both ends take in: a server whose answer is
	// not read cannot have written all of it
	const declared = 64 << 20
	var sent int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(declared))
		w.WriteHeader(http.StatusOK)
		chunk := []byte(strings.Repeat("A", 64<<10))
		for sent < declared {
			n, err := w.Write(chunk)
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
	require.Less(t, sent, declared, "the client must stop the transfer instead of reading it")
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

// What a server sends reaches the log as one printable line of a bounded length.
func TestRuleSetLogText(t *testing.T) {
	t.Parallel()
	require.Equal(t, "unexpected status: 404 Not?Found??[31m", logText(E.New("unexpected status: 404 Not\nFound\r\x1b[31m")))
	require.Equal(t, "rules[0]: unknown rule type: x?y", logText(E.New("rules[0]: unknown rule type: x\x00y")))
	long := logText(E.New(strings.Repeat("\u044f", 600)))
	require.LessOrEqual(t, len(long), 515)
	require.True(t, strings.HasSuffix(long, "..."))
	require.True(t, utf8.ValidString(long))
	require.NotContains(t, long, "?")
}

// Big lists are updated one at a time, small ones together: two sets that hold a big list
// each never download at once, two small ones do. What was loaded tells its size.
func TestRemoteRuleSetBigOneAtATime(t *testing.T) {
	var bigInFlight, bigMost, smallInFlight, smallMost atomic.Int32
	raise := func(most *atomic.Int32, now int32) {
		for {
			seen := most.Load()
			if now <= seen || most.CompareAndSwap(seen, now) {
				return
			}
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inFlight, most := &smallInFlight, &smallMost
		if r.URL.Path == "/big" {
			inFlight, most = &bigInFlight, &bigMost
		}
		raise(most, inFlight.Add(1))
		defer inFlight.Add(-1)
		time.Sleep(200 * time.Millisecond)
		io.WriteString(w, testSourceSet)
	}))
	defer server.Close()
	var sets []*RemoteRuleSet
	for _, path := range []string{"/big", "/big", "/small", "/small"} {
		set := newTestRuleSet(server.URL + path)
		set.options.Format = C.RuleSetFormatSource
		if path == "/big" {
			set.contentSize.Store(heavyRuleSetSize)
		}
		sets = append(sets, set)
	}
	var group sync.WaitGroup
	for _, set := range sets {
		group.Add(1)
		go func() {
			defer group.Done()
			require.True(t, set.updateOnce())
		}()
	}
	group.Wait()
	require.EqualValues(t, 1, bigMost.Load(), "two big lists were downloaded at once")
	require.EqualValues(t, 2, smallMost.Load())
	require.EqualValues(t, len(testSourceSet), sets[0].contentSize.Load())
}

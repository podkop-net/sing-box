package group

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// downloadServer answers the URL test at once and the download test as its mode says:
// "full" (the whole size), "short" (a 1000-byte body), "stall" (16 KB, then nothing, as a
// frozen connection) or "close" (16 KB, then the connection is closed).
type downloadServer struct {
	*httptest.Server
	mode atomic.Value
	gets atomic.Int32
}

func newDownloadServer(t *testing.T, mode string) *downloadServer {
	s := &downloadServer{}
	s.mode.Store(mode)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.gets.Add(1)
		mode := s.mode.Load().(string)
		if r.URL.Path != "/" {
			mode = r.URL.Path[1:] // a mode by path, for several in one server
		}
		switch mode {
		case "full":
			w.Header().Set("Content-Length", strconv.Itoa(urltest.DownloadTestSize))
			w.Write(make([]byte, urltest.DownloadTestSize))
		case "short":
			w.Header().Set("Content-Length", "1000")
			w.Write(make([]byte, 1000))
		case "stall":
			w.Header().Set("Content-Length", strconv.Itoa(urltest.DownloadTestSize))
			w.Write(make([]byte, 16384))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case "close":
			w.Header().Set("Content-Length", strconv.Itoa(urltest.DownloadTestSize))
			w.Write(make([]byte, 16384))
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Server.Close)
	return s
}

// dialTo makes a member whose every connection reaches server, whatever the destination.
func dialTo(server *downloadServer) func(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return func(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
}

func shortDownloadTimeout(t *testing.T) {
	saved := downloadTestTimeout
	downloadTestTimeout = 300 * time.Millisecond
	t.Cleanup(func() { downloadTestTimeout = saved })
}

// a dies; b, the next by delay, is frozen after 16 KB: the group passes it over for c,
// which downloads the whole test, for TCP and UDP alike. b keeps its test result and is not
// tested again until a newer result comes, then once per result.
func TestURLTestDownloadCheckPassesOverFrozenMember(t *testing.T) {
	shortDownloadTimeout(t)
	full := newDownloadServer(t, "full")
	frozen := newDownloadServer(t, "stall")
	var aDead atomic.Bool
	a := newTestMember(C.TypeVLESS, "a", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if aDead.Load() {
			return nil, syscall.ECONNREFUSED
		}
		return dialTo(full)(ctx, network, destination)
	})
	b := newTestMember(C.TypeVLESS, "b", dialTo(frozen))
	c := newTestMember(C.TypeVLESS, "c", dialTo(full))
	urlTest, group := newTestURLTest(t, full.URL, a, b, c)
	group.downloadLink = full.URL

	aDead.Store(true)
	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	waitSelected(t, group, "c")
	require.Equal(t, "c", group.selectedOutboundUDP.Load().Tag())
	require.Equal(t, int32(1), frozen.gets.Load())
	require.Equal(t, int32(1), full.gets.Load())
	require.NotNil(t, group.history.LoadURLTestHistory("b"), "the frozen member lost its test result")
	_, isFrozen := group.frozen.Load()["b"]
	require.True(t, isFrozen)

	group.performUpdateCheck()
	require.Equal(t, int32(1), frozen.gets.Load(), "tested again without a new test result")
	require.Equal(t, "c", group.selectedOutboundTCP.Load().Tag())

	// the next periodic result: b is tried once more, fails again, c stays
	group.history.StoreURLTestHistory("b", &adapter.URLTestHistory{Time: time.Now(), Delay: 110})
	group.performUpdateCheck()
	require.Equal(t, int32(2), frozen.gets.Load())
	require.Equal(t, "c", group.selectedOutboundTCP.Load().Tag())

	// b recovers: the result after that lets it back, and it is the faster one
	frozen.mode.Store("full")
	group.history.StoreURLTestHistory("b", &adapter.URLTestHistory{Time: time.Now(), Delay: 110})
	group.performUpdateCheck()
	require.Equal(t, int32(3), frozen.gets.Load())
	require.Equal(t, "b", group.selectedOutboundTCP.Load().Tag())
	_, isFrozen = group.frozen.Load()["b"]
	require.False(t, isFrozen)
}

// The only other member is frozen: better than a dead one, the group takes it.
func TestURLTestDownloadCheckFrozenBeatsDead(t *testing.T) {
	shortDownloadTimeout(t)
	full := newDownloadServer(t, "full")
	frozen := newDownloadServer(t, "stall")
	a := newTestMember(C.TypeVLESS, "a", dialRefused)
	b := newTestMember(C.TypeVLESS, "b", dialTo(frozen))
	urlTest, group := newTestURLTest(t, full.URL, a, b)
	group.downloadLink = full.URL

	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	require.Error(t, err)
	waitSelected(t, group, "b")
	require.Equal(t, int32(1), frozen.gets.Load())
}

// A connection closed after 16 KB fails the test as a stall does, and at once.
func TestURLTestDownloadCheckClosedEarly(t *testing.T) {
	full := newDownloadServer(t, "full")
	closing := newDownloadServer(t, "close")
	a := newTestMember(C.TypeVLESS, "a", dialRefused)
	b := newTestMember(C.TypeVLESS, "b", dialTo(closing))
	c := newTestMember(C.TypeVLESS, "c", dialTo(full))
	urlTest, group := newTestURLTest(t, full.URL, a, b, c)
	group.downloadLink = full.URL

	start := time.Now()
	_, _ = urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	waitSelected(t, group, "c")
	require.Less(t, time.Since(start), 2*time.Second)
}

// A member taken as the last resort, frozen, is tested again when its next result makes it
// a candidate: a member that has recovered meanwhile, even one within the tolerance, gets
// its turn instead of being kept out by the member in use.
func TestURLTestDownloadCheckFrozenLastResortRetested(t *testing.T) {
	shortDownloadTimeout(t)
	full := newDownloadServer(t, "full")
	frozen := newDownloadServer(t, "stall")
	b := newTestMember(C.TypeVLESS, "b", dialTo(full))
	a := newTestMember(C.TypeVLESS, "a", dialTo(frozen))
	_, group := newTestURLTest(t, full.URL, b, a) // b in use, healthy; a frozen
	group.downloadLink = full.URL

	// b loses its result (a failed test on a lossy link); a fails the download test and is
	// taken as the last resort
	group.history.DeleteURLTestHistory("b")
	group.performUpdateCheck()
	require.Equal(t, "a", group.selectedOutboundTCP.Load().Tag())
	require.Equal(t, int32(1), frozen.gets.Load())

	// the next round: both have results again, b within the tolerance of a
	group.history.StoreURLTestHistory("a", &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	group.history.StoreURLTestHistory("b", &adapter.URLTestHistory{Time: time.Now(), Delay: 30})
	group.performUpdateCheck()
	require.Equal(t, int32(2), frozen.gets.Load(), "the frozen member in use was not tested again")
	require.Equal(t, int32(1), full.gets.Load())
	require.Equal(t, "b", group.selectedOutboundTCP.Load().Tag())
}

// A test that could not run says nothing about the member: a URL that answers with a
// status, or with a body shorter than the size, holds no member back.
func TestURLTestDownloadCheckInconclusive(t *testing.T) {
	for _, mode := range []string{"short", "missing"} {
		t.Run(mode, func(t *testing.T) {
			server := newDownloadServer(t, mode)
			a := newTestMember(C.TypeVLESS, "a", dialRefused)
			b := newTestMember(C.TypeVLESS, "b", dialTo(server))
			urlTest, group := newTestURLTest(t, server.URL, a, b)
			group.downloadLink = server.URL + "/" + mode

			_, _ = urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
			waitSelected(t, group, "b")
			require.Equal(t, int32(1), server.gets.Load())
			require.Empty(t, group.frozen.Load())
		})
	}
}

// While a selection waits (a download test runs), failed dials do not pile up waiting
// selections: one is pending at most.
func TestURLTestRequestUpdateCheckCoalesces(t *testing.T) {
	link, _ := testURL(t, 0)
	a := newTestMember(C.TypeVLESS, "a", dialRefused)
	b := newTestMember(C.TypeVLESS, "b", dialWorking)
	urlTest, group := newTestURLTest(t, link, a, b)

	group.updateAccess.Lock() // as a download test would
	before := runtime.NumGoroutine()
	for range 50 {
		_, _ = urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	}
	time.Sleep(50 * time.Millisecond)
	require.LessOrEqual(t, runtime.NumGoroutine()-before, 2, "selections piled up")
	group.updateAccess.Unlock()
	waitSelected(t, group, "b")
}

// The Clash API's update check and round return without waiting for the selection.
func TestURLTestClashPathsDoNotWait(t *testing.T) {
	link, _ := testURL(t, 0)
	a := newTestMember(C.TypeVLESS, "a", dialWorking)
	urlTest, group := newTestURLTest(t, link, a)
	group.updateAccess.Lock()
	defer group.updateAccess.Unlock()
	done := make(chan struct{})
	go func() {
		urlTest.PerformUpdateCheck()
		_, _ = group.URLTest(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the Clash API paths waited for the selection")
	}
}

// While the selected member has no test result (it is down) and the selection waits for a
// download test, connections go by the plain choice.
func TestURLTestDialFallsBackWhileSelectionPending(t *testing.T) {
	link, _ := testURL(t, 0)
	a := newTestMember(C.TypeVLESS, "a", dialRefused)
	b := newTestMember(C.TypeVLESS, "b", dialWorking)
	urlTest, group := newTestURLTest(t, link, a, b)
	group.downloadLink = link
	group.history.DeleteURLTestHistory("a")
	group.updateAccess.Lock() // the selection is busy
	defer group.updateAccess.Unlock()

	conn, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr(link[len("http://"):]))
	require.NoError(t, err)
	conn.Close()
	require.Equal(t, int32(0), a.dials.Load())
	require.Equal(t, int32(1), b.dials.Load())
}

// A test URL whose body is shorter than the size cannot show a freeze: the test is
// inconclusive and the member is taken.
func TestURLTestDownloadCheckShortBodyPasses(t *testing.T) {
	short := newDownloadServer(t, "short")
	a := newTestMember(C.TypeVLESS, "a", dialRefused)
	b := newTestMember(C.TypeVLESS, "b", dialTo(short))
	urlTest, group := newTestURLTest(t, short.URL, a, b)
	group.downloadLink = short.URL

	_, _ = urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	waitSelected(t, group, "b")
	require.Equal(t, int32(1), short.gets.Load())
	require.Empty(t, group.frozen.Load())
}

// Without a test URL the group switches as before, downloading nothing.
func TestURLTestDownloadCheckOff(t *testing.T) {
	frozen := newDownloadServer(t, "stall")
	a := newTestMember(C.TypeVLESS, "a", dialRefused)
	b := newTestMember(C.TypeVLESS, "b", dialTo(frozen))
	urlTest, group := newTestURLTest(t, frozen.URL, a, b)
	require.Empty(t, group.downloadLink)

	_, _ = urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("1.2.3.4:443"))
	waitSelected(t, group, "b")
	require.Equal(t, int32(0), frozen.gets.Load())
}

// download_url sets the group's test URL: absent, the environment's is taken; empty, the
// test is off; a URL the test could not use is an error of the configuration.
func TestURLTestDownloadURLOption(t *testing.T) {
	environment := downloadTestLink
	t.Cleanup(func() { downloadTestLink = environment })
	downloadTestLink = "http://environment.test/64k"
	for _, testCase := range []struct {
		name   string
		option *string
		link   string
		err    bool
	}{
		{"absent", nil, "http://environment.test/64k", false},
		{"empty", common.Ptr(""), "", false},
		{"https", common.Ptr("https://download.test/64k"), "https://download.test/64k", false},
		{"http with a port", common.Ptr("http://download.test:8080/64k"), "http://download.test:8080/64k", false},
		{"no scheme", common.Ptr("download.test/64k"), "", true},
		{"not http", common.Ptr("ftp://download.test/64k"), "", true},
		{"no host", common.Ptr("https:///64k"), "", true},
		{"unparsable", common.Ptr("://download.test"), "", true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			member := newTestMember(C.TypeVLESS, "a", dialWorking)
			ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
			manager := &testOutboundManager{members: map[string]adapter.Outbound{"a": member}}
			ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)
			created, err := NewURLTest(ctx, nil, log.NewNOPFactory().NewLogger("urltest"), "auto", option.URLTestOutboundOptions{
				Outbounds:   []string{"a"},
				DownloadURL: testCase.option,
			})
			if testCase.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			urlTest := created.(*URLTest)
			require.NoError(t, urlTest.Start())
			require.Equal(t, testCase.link, urlTest.group.downloadLink)
		})
	}
}

type warnLog struct {
	access sync.Mutex
	lines  []string
}

func (l *warnLog) WriteMessage(level log.Level, message string) {
	if level != log.LevelWarn {
		return
	}
	l.access.Lock()
	defer l.access.Unlock()
	l.lines = append(l.lines, message)
}

func (l *warnLog) take() []string {
	l.access.Lock()
	defer l.access.Unlock()
	lines := l.lines
	l.lines = nil
	return lines
}

// A download test URL from the environment that the test could not use does not stop the
// start, as a download_url does: the group warns once, when it is created, and works
// without the download test.
func TestURLTestDownloadURLEnvironmentUnusable(t *testing.T) {
	environment := downloadTestLink
	t.Cleanup(func() { downloadTestLink = environment })
	for _, testCase := range []struct {
		name string
		link string
		warn bool
	}{
		{"usable", "/full", false}, // on the test server
		{"unset", "", false},
		{"no scheme", "environment.test/64k", true},
		{"not http", "ftp://environment.test/64k", true},
		{"no host", "https:///64k", true},
		{"unparsable", "://environment.test", true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			writer := &warnLog{}
			factory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now()}, io.Discard, "", writer, false)
			factory.SetLevel(log.LevelDebug)
			require.NoError(t, factory.Start())
			defer factory.Close()

			working := newDownloadServer(t, "full")
			link := testCase.link
			if strings.HasPrefix(link, "/") {
				link = working.URL + link
			}
			downloadTestLink = link
			a := newTestMember(C.TypeVLESS, "a", dialTo(working))
			b := newTestMember(C.TypeVLESS, "b", dialTo(working))
			history := urltest.NewHistoryStorage()
			history.StoreURLTestHistory("a", &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
			history.StoreURLTestHistory("b", &adapter.URLTestHistory{Time: time.Now(), Delay: 110})
			ctx := service.ContextWithPtr(context.Background(), history)
			manager := &testOutboundManager{members: map[string]adapter.Outbound{"a": a, "b": b}}
			ctx = service.ContextWith[adapter.OutboundManager](ctx, manager)
			created, err := NewURLTest(ctx, nil, factory.NewLogger("urltest"), "auto", option.URLTestOutboundOptions{
				Outbounds: []string{"a", "b"},
				URL:       working.URL,
			})
			require.NoError(t, err)
			urlTest := created.(*URLTest)
			require.NoError(t, urlTest.Start())
			lines := writer.take()
			if !testCase.warn {
				require.Empty(t, lines)
				require.Equal(t, link, urlTest.group.downloadLink)
				return
			}
			require.Len(t, lines, 1)
			require.Contains(t, lines[0], "SING_BOX_URLTEST_DOWNLOAD_URL")
			require.Contains(t, lines[0], "download test is off")
			require.Empty(t, urlTest.group.downloadLink)

			// the group selects a member without a download and says nothing more of the URL
			urlTest.group.performUpdateCheck()
			require.Equal(t, "a", urlTest.group.selectedOutboundTCP.Load().Tag())
			require.Empty(t, writer.take())
			require.Equal(t, int32(0), working.gets.Load())
		})
	}
}

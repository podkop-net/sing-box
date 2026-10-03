package group

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// fakeServer stands for a proxy server: each connection is a pipe; the server reads the
// first write and answers it with answers[host], or never ("" or missing). Connections to
// the URL test go to the test server, unless the test is to fail.
type fakeServer struct {
	testHost  string
	failTest  atomic.Bool
	access    sync.Mutex
	answers   map[string]string
	firstByte map[string]string // written before the client writes (a server that speaks first)
	readErr   map[string]error  // returned to the client's reads instead of an answer
}

func newFakeServer(link string) *fakeServer {
	parsed, _ := url.Parse(link)
	return &fakeServer{
		testHost:  parsed.Host,
		answers:   make(map[string]string),
		firstByte: make(map[string]string),
		readErr:   make(map[string]error),
	}
}

type failingConn struct {
	net.Conn
	err error
}

func (c *failingConn) Read([]byte) (int, error) {
	return 0, c.err
}

func (s *fakeServer) dial(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if destination.String() == s.testHost {
		if s.failTest.Load() {
			return nil, errors.New("the URL test failed")
		}
		return dialWorking(ctx, network, destination)
	}
	s.access.Lock()
	answer, first, readErr := s.answers[destination.AddrString()], s.firstByte[destination.AddrString()], s.readErr[destination.AddrString()]
	s.access.Unlock()
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		if first != "" {
			if _, err := server.Write([]byte(first)); err != nil {
				return
			}
		}
		buffer := make([]byte, 1024)
		if _, err := server.Read(buffer); err != nil {
			return
		}
		if answer != "" {
			if _, err := server.Write([]byte(answer)); err != nil {
				return
			}
		}
		io.Copy(io.Discard, server)
	}()
	if readErr != nil {
		return &failingConn{Conn: client, err: readErr}, nil
	}
	return client, nil
}

// readAll keeps reading conn, as the copy loop would, and reports the first data and the
// end.
func readAll(conn net.Conn) (data chan string, done chan error) {
	data, done = make(chan string, 1), make(chan error, 1)
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, err := conn.Read(buffer)
			if n > 0 {
				select {
				case data <- string(buffer[:n]):
				default:
				}
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()
	return
}

func dialAndWrite(t *testing.T, urlTest *URLTest, destination string) net.Conn {
	conn, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr(destination))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	_, err = conn.Write([]byte("request"))
	require.NoError(t, err)
	return conn
}

func waitSelectedWithin(t *testing.T, group *URLTestGroup, tag string, within time.Duration) {
	t.Helper()
	require.Eventually(t, func() bool {
		return group.selectedOutboundTCP.Load().Tag() == tag
	}, within, 10*time.Millisecond, "selected outbound is not %s", tag)
}

// A member that accepts connections and never answers: one retransmission timeout after the
// client wrote, the member is tested out of turn, the test fails, the group switches and
// closes the connection that waits for the answer.
func TestURLTestUnansweredSwitches(t *testing.T) {
	t.Parallel()
	link, _ := testURL(t, 0)
	server := newFakeServer(link)
	server.failTest.Store(true)
	silent := newTestMember(C.TypeHysteria2, "silent", server.dial)
	spare := newTestMember(C.TypeHysteria2, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, silent, spare)

	start := time.Now()
	conn := dialAndWrite(t, urlTest, "example.com:443")
	_, done := readAll(conn)
	waitSelectedWithin(t, group, "spare", 3*time.Second)
	require.Greater(t, time.Since(start), time.Second, "the member was tested before its timeout")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the unanswered connection was not closed")
	}
}

// The member answers another connection that began later: the silence of the first is
// its destination's, nothing is tested.
func TestURLTestUnansweredRefutedByLaterAnswer(t *testing.T) {
	t.Parallel()
	link, requests := testURL(t, 0)
	server := newFakeServer(link)
	server.answers["fast.example"] = "answer"
	member := newTestMember(C.TypeVLESS, "member", server.dial)
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, member, spare)

	slow := dialAndWrite(t, urlTest, "slow.example:443")
	readAll(slow)
	time.Sleep(100 * time.Millisecond)
	fast := dialAndWrite(t, urlTest, "fast.example:443")
	data, _ := readAll(fast)
	require.Equal(t, "answer", <-data)

	time.Sleep(1500 * time.Millisecond)
	require.Equal(t, int32(0), requests.Load(), "the member was tested")
	require.Equal(t, "member", group.selectedOutboundTCP.Load().Tag())
}

// A destination that stays silent while the member passes its test counts no more for an
// interval: the member is tested once, not for every connection to it.
func TestURLTestUnansweredDestinationPassed(t *testing.T) {
	t.Parallel()
	link, requests := testURL(t, 0)
	server := newFakeServer(link)
	member := newTestMember(C.TypeVLESS, "member", server.dial)
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, member, spare)

	readAll(dialAndWrite(t, urlTest, "dead.example:443"))
	require.Eventually(t, func() bool { return requests.Load() == 1 }, 3*time.Second, 10*time.Millisecond)
	readAll(dialAndWrite(t, urlTest, "dead.example:443"))
	time.Sleep(1500 * time.Millisecond)
	require.Equal(t, int32(1), requests.Load(), "the member was tested again for the same destination")
	require.Equal(t, "member", group.selectedOutboundTCP.Load().Tag())
}

// A reset before any answer is evidence at once; an EOF is not.
func TestURLTestResetBeforeAnswer(t *testing.T) {
	t.Parallel()
	link, requests := testURL(t, 0)
	server := newFakeServer(link)
	server.readErr["reset.example"] = syscall.ECONNRESET
	server.readErr["eof.example"] = io.EOF
	member := newTestMember(C.TypeVLESS, "member", server.dial)
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, _ := newTestURLTest(t, link, member, spare)

	_, done := readAll(dialAndWrite(t, urlTest, "eof.example:443"))
	require.ErrorIs(t, <-done, io.EOF)
	time.Sleep(200 * time.Millisecond)
	require.Equal(t, int32(0), requests.Load(), "an EOF made the member tested")

	_, done = readAll(dialAndWrite(t, urlTest, "reset.example:443"))
	<-done
	require.Eventually(t, func() bool { return requests.Load() == 1 }, 500*time.Millisecond, 10*time.Millisecond,
		"a reset before the answer did not make the member tested at once")
}

// A server that speaks first has answered before the client wrote anything: its later
// silence says nothing.
func TestURLTestServerFirstNotWatched(t *testing.T) {
	t.Parallel()
	link, requests := testURL(t, 0)
	server := newFakeServer(link)
	server.firstByte["smtp.example"] = "220 ready"
	member := newTestMember(C.TypeVLESS, "member", server.dial)
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, _ := newTestURLTest(t, link, member, spare)

	conn, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("smtp.example:25"))
	require.NoError(t, err)
	defer conn.Close()
	data, _ := readAll(conn)
	require.Equal(t, "220 ready", <-data)
	_, err = conn.Write([]byte("EHLO"))
	require.NoError(t, err)
	time.Sleep(1500 * time.Millisecond)
	require.Equal(t, int32(0), requests.Load())
}

// The clock runs from the last write before the answer: a first flight in pieces is not
// overdue while its pieces keep coming.
func TestURLTestUnansweredClockFromLastWrite(t *testing.T) {
	t.Parallel()
	link, requests := testURL(t, 0)
	server := newFakeServer(link)
	member := newTestMember(C.TypeVLESS, "member", server.dial)
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, _ := newTestURLTest(t, link, member, spare)

	conn, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("pieces.example:443"))
	require.NoError(t, err)
	defer conn.Close()
	readAll(conn)
	for i := 0; i < 3; i++ {
		_, err = conn.Write([]byte("piece"))
		require.NoError(t, err)
		time.Sleep(700 * time.Millisecond)
	}
	require.Equal(t, int32(0), requests.Load(), "overdue while the client was still writing")
	require.Eventually(t, func() bool { return requests.Load() == 1 }, 2*time.Second, 10*time.Millisecond)
}

// RFC 6298: the first sample sets SRTT and RTTVAR, later ones are smoothed; a late answer
// gives no sample and doubles the timeout until an answer comes in time.
func TestURLTestRetransmissionTimeout(t *testing.T) {
	link, _ := testURL(t, 0)
	member := newTestMember(C.TypeVLESS, "member", dialWorking)
	_, group := newTestURLTest(t, link, member)
	responses := group.memberResponses("member")

	responses.access.Lock()
	defer responses.access.Unlock()
	require.Equal(t, 10*time.Millisecond+20*time.Millisecond+time.Second, group.retransmissionTimeout(responses, "member"))
	responses.sample(100 * time.Millisecond)
	require.Equal(t, (7*10*time.Millisecond+100*time.Millisecond)/8, responses.smoothed)
	require.Equal(t, (3*5*time.Millisecond+90*time.Millisecond)/4, responses.variation)
	base := group.retransmissionTimeout(responses, "member")
	responses.backoff = 2
	require.Equal(t, 4*base, group.retransmissionTimeout(responses, "member"))
	responses.backoff = 10
	require.Equal(t, C.TCPTimeout, group.retransmissionTimeout(responses, "member"))
}

// waitCountingConn has a read waiter and counts its use: the copy loop reaches it once the
// answer began.
type waitCountingConn struct {
	net.Conn
	options N.ReadWaitOptions
	waits   atomic.Int32
}

func (c *waitCountingConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.options = options
	return false
}

func (c *waitCountingConn) WaitReadBuffer() (*buf.Buffer, error) {
	c.waits.Add(1)
	buffer := c.options.NewBuffer()
	n, err := c.Conn.Read(buffer.FreeBytes())
	if n > 0 {
		buffer.Truncate(n)
		return buffer, nil
	}
	buffer.Release()
	return nil, err
}

// The copy loop reads through the connection until the answer begins, then below it.
func TestURLTestUnansweredUnwrappedAfterAnswer(t *testing.T) {
	t.Parallel()
	link, _ := testURL(t, 0)
	var inner *waitCountingConn
	remote := make(chan net.Conn, 1)
	member := newTestMember(C.TypeVLESS, "member", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		client, server := net.Pipe()
		inner = &waitCountingConn{Conn: client}
		remote <- server
		return inner, nil
	})
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, _ := newTestURLTest(t, link, member, spare)

	conn, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	require.NoError(t, err)
	server := <-remote
	go func() {
		buffer := make([]byte, 64)
		server.Read(buffer)
		server.Write([]byte("first"))
		server.Write([]byte(" second"))
		server.Close()
	}()
	_, err = conn.Write([]byte("request"))
	require.NoError(t, err)
	var output bytesBuffer
	_, err = bufio.Copy(&output, conn)
	require.NoError(t, err)
	require.Equal(t, "first second", output.String())
	require.Positive(t, inner.waits.Load(), "the copy loop kept reading through the watching connection")
}

type bytesBuffer struct {
	access sync.Mutex
	data   []byte
}

func (b *bytesBuffer) Write(p []byte) (int, error) {
	b.access.Lock()
	defer b.access.Unlock()
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *bytesBuffer) String() string {
	b.access.Lock()
	defer b.access.Unlock()
	return string(b.data)
}

// A member declared down by a failed dial (S1) gets its connections without an answer
// closed, preconnects included.
func TestURLTestVerdictClosesUnanswered(t *testing.T) {
	t.Parallel()
	link, _ := testURL(t, 0)
	server := newFakeServer(link)
	var refuse atomic.Bool
	member := newTestMember(C.TypeVLESS, "member", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if refuse.Load() {
			return nil, syscall.ECONNREFUSED
		}
		return server.dial(ctx, network, destination)
	})
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, member, spare)

	preconnect, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("preconnect.example:443"))
	require.NoError(t, err)
	defer preconnect.Close()
	_, done := readAll(preconnect)

	refuse.Store(true)
	_, err = urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	require.Error(t, err)
	waitSelectedWithin(t, group, "spare", 2*time.Second)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the preconnect of the member declared down was not closed")
	}
}

// Timers of a closed group do nothing.
func TestURLTestUnansweredAfterClose(t *testing.T) {
	t.Parallel()
	link, requests := testURL(t, 0)
	server := newFakeServer(link)
	member := newTestMember(C.TypeVLESS, "member", server.dial)
	spare := newTestMember(C.TypeVLESS, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, member, spare)

	readAll(dialAndWrite(t, urlTest, "example.com:443"))
	require.NoError(t, group.Close())
	time.Sleep(1500 * time.Millisecond)
	require.Equal(t, int32(0), requests.Load())
}

// A false alarm of a connection without an answer does not delay the test of a failed dial:
// the two keep their pauses apart.
func TestURLTestUnansweredPauseApart(t *testing.T) {
	t.Parallel()
	link, requests := testURL(t, 0)
	server := newFakeServer(link)
	var refuse atomic.Bool
	member := newTestMember(C.TypeSOCKS, "member", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if refuse.Load() && destination.String() != server.testHost {
			return nil, syscall.ECONNREFUSED
		}
		return server.dial(ctx, network, destination)
	})
	spare := newTestMember(C.TypeSOCKS, "spare", dialWorking)
	urlTest, _ := newTestURLTest(t, link, member, spare)

	readAll(dialAndWrite(t, urlTest, "dead.example:443"))
	require.Eventually(t, func() bool { return requests.Load() == 1 }, 3*time.Second, 10*time.Millisecond)
	time.Sleep(100 * time.Millisecond) // the test has passed: the pause of the unanswered alarms runs

	refuse.Store(true)
	_, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("other.example:443"))
	require.Error(t, err)
	require.Eventually(t, func() bool { return requests.Load() == 2 }, 500*time.Millisecond, 10*time.Millisecond,
		"the failed dial waited for the pause of an unanswered connection")
}

// An error the server sent back (a destination it could not reach) is no evidence: the
// server answered.
func TestURLTestServerErrorNoEvidence(t *testing.T) {
	t.Parallel()
	link, requests := testURL(t, 0)
	server := newFakeServer(link)
	server.readErr["refused.example"] = errors.New("remote error: connection refused")
	member := newTestMember(C.TypeHysteria2, "member", server.dial)
	spare := newTestMember(C.TypeHysteria2, "spare", dialWorking)
	urlTest, _ := newTestURLTest(t, link, member, spare)

	_, done := readAll(dialAndWrite(t, urlTest, "refused.example:443"))
	<-done
	time.Sleep(200 * time.Millisecond)
	require.Equal(t, int32(0), requests.Load())
}

// With every member down the selection stays, and so do the connections waiting through it.
func TestURLTestUnansweredKeptWhenAllDown(t *testing.T) {
	t.Parallel()
	link, _ := testURL(t, 0)
	server := newFakeServer(link)
	member := newTestMember(C.TypeVLESS, "member", server.dial)
	spare := newTestMember(C.TypeVLESS, "spare", server.dial)
	urlTest, group := newTestURLTest(t, link, member, spare)

	_, done := readAll(dialAndWrite(t, urlTest, "example.com:443"))
	group.history.DeleteURLTestHistory("member")
	group.history.DeleteURLTestHistory("spare")
	group.performUpdateCheck()
	require.Equal(t, "member", group.selectedOutboundTCP.Load().Tag())
	select {
	case err := <-done:
		t.Fatal("the connection was closed although the group did not switch: ", err)
	case <-time.After(300 * time.Millisecond):
	}
}

// Before the answer the copy loop still waits with the read waiter of the connection below
// (no buffer held while the server is silent), and the first data counts as the answer.
func TestURLTestUnansweredKeepsReadWaiter(t *testing.T) {
	t.Parallel()
	link, _ := testURL(t, 0)
	parsed, _ := url.Parse(link)
	var inner *waitCountingConn
	remote := make(chan net.Conn, 1)
	member := newTestMember(C.TypeTrojan, "member", func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
		if destination.String() == parsed.Host {
			return dialWorking(ctx, network, destination)
		}
		client, server := net.Pipe()
		inner = &waitCountingConn{Conn: client}
		remote <- server
		return inner, nil
	})
	spare := newTestMember(C.TypeTrojan, "spare", dialWorking)
	urlTest, group := newTestURLTest(t, link, member, spare)

	conn, err := urlTest.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	require.NoError(t, err)
	server := <-remote
	request := make(chan struct{})
	answer := make(chan struct{})
	go func() {
		buffer := make([]byte, 64)
		server.Read(buffer)
		close(request)
		<-answer
		server.Write([]byte("answer"))
		server.Close()
	}()
	done := make(chan error, 1)
	var output bytesBuffer
	go func() {
		_, err := bufio.Copy(&output, conn)
		done <- err
	}()
	_, err = conn.Write([]byte("request"))
	require.NoError(t, err)
	<-request
	require.Eventually(t, func() bool { return inner.waits.Load() > 0 }, time.Second, 5*time.Millisecond,
		"the copy loop waited through the watching connection with its own buffer")
	close(answer)
	require.NoError(t, <-done)
	require.Equal(t, "answer", output.String())
	responses := group.memberResponses("member")
	responses.access.Lock()
	defer responses.access.Unlock()
	require.Empty(t, responses.pending, "the answer that came through the read waiter was not seen")
}

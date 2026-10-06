package v2rayxhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/readwait"
	"github.com/sagernet/sing/common/baderror"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// session is the net.Conn of one XHTTP session: a download (the body of a GET,
// or of the stream-one request) and an upload (a streamed request body, or
// packet-up requests).
//
// Every request of the session runs on the session's own context, not on the
// context of the dial: a dial context is done once the dial returns, and the
// session must outlive it. Cancelling the session context aborts every request
// in flight; Close does it once what was written has been sent.
type session struct {
	ctx      context.Context
	cancel   context.CancelFunc
	closed   atomic.Bool
	tearOnce sync.Once
	// unanswered: data was written and no download data has been read since.
	unanswered atomic.Bool

	failure atomic.Pointer[failureBox]

	clientAccess sync.Mutex
	clients      []*poolClient
	counted      []*poolClient

	downloadOnce  sync.Once
	downloadReady chan struct{}
	download      io.ReadCloser
	downloadErr   error

	// The read waiter waits for download data on a small probe instead of the
	// copy buffer: what the probe read is delivered first. Both are used by
	// the one reader of the session only.
	probe      []byte
	pending    []byte
	pendingErr error
	flowing    bool

	// streamBody is the body of the request that streams the upload: closing it
	// with an error is what releases a Write blocked on a failed request.
	streamBody   *io.PipeReader
	streamUpload *io.PipeWriter
	packetUpload *uploader
	// uploadWritten is closed when the upload stream is over: the request
	// written to its end (stream-one), answered to its end (stream-up), or
	// failed.
	uploadWritten chan struct{}
	writtenOnce   sync.Once

	connected  chan struct{}
	localAddr  net.Addr
	remoteAddr net.Addr
}

type failureBox struct {
	err error
}

// dialDepthKey counts, in the context of a session's requests, the sessions
// that context has passed through: a download detour that leads back to its
// own outbound would otherwise dial itself without end.
type dialDepthKey struct{}

const maxDialDepth = 4

func dialDepth(ctx context.Context) int {
	depth, _ := ctx.Value(dialDepthKey{}).(int)
	return depth
}

func newSession(depth int) *session {
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), dialDepthKey{}, depth+1))
	return &session{
		ctx:           ctx,
		cancel:        cancel,
		downloadReady: make(chan struct{}),
		connected:     make(chan struct{}),
		uploadWritten: make(chan struct{}),
	}
}

// closeLinger bounds how long a closed session stays to send what was written
// to it before the Close; closeGrace is how long it stays after that when the
// server has not answered the data, for the server to forward it.
const (
	closeLinger = 5 * time.Second
	closeGrace  = time.Second
)

// withUploadTrace reports the end of the request that streams the upload.
func (s *session) withUploadTrace(ctx context.Context) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) {
			s.writtenOnce.Do(func() { close(s.uploadWritten) })
		},
	})
}

// hold makes the session keep a client (counted as running by get) until it
// closes.
func (s *session) hold(client *poolClient) {
	s.clientAccess.Lock()
	defer s.clientAccess.Unlock()
	if s.closed.Load() {
		client.release()
		return
	}
	s.clients = append(s.clients, client)
}

// count makes the session end, when it closes, the session count get(true)
// started on a client.
func (s *session) count(client *poolClient) {
	s.clientAccess.Lock()
	defer s.clientAccess.Unlock()
	if s.closed.Load() {
		client.endSession()
		return
	}
	s.counted = append(s.counted, client)
}

// withConnectTrace reports the first connection a request of the session got:
// the dial returns then, before any response, since the server may hold the
// response of a download until the first upload arrives.
func (s *session) withConnectTrace(ctx context.Context) context.Context {
	var once sync.Once
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			once.Do(func() {
				s.localAddr = info.Conn.LocalAddr()
				s.remoteAddr = info.Conn.RemoteAddr()
				close(s.connected)
			})
		},
	})
}

// waitConnected waits for the download (or the stream-one request) to get its
// connection, for the session to fail, or for the dial to be given up.
func (s *session) waitConnected(ctx context.Context) error {
	select {
	case <-s.connected:
		return nil
	case <-s.downloadReady:
		select {
		case <-s.connected:
			return nil
		default:
		}
		return s.downloadErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// startDownload sends the request whose response body is the download.
func (s *session) startDownload(client *poolClient, request *http.Request) {
	request = request.WithContext(s.withConnectTrace(request.Context()))
	go func() {
		response, err := client.roundTrip(request)
		if err != nil {
			s.fail(E.Cause(err, "xhttp: download"))
			return
		}
		if response.StatusCode != http.StatusOK {
			// Not read to its end first: the body of an error may never end,
			// and a read of the session would wait for it.
			response.Body.Close()
			s.fail(E.New("xhttp: download: unexpected status ", response.Status))
			return
		}
		if !s.setDownload(response.Body, nil) {
			response.Body.Close()
		}
	}()
}

// startStreamUpload sends the request whose body streams the upload
// (stream-up). Its response carries only the server's keep-alive padding.
//
// Unlike Xray's client, which does not look at the answer to this request, a
// failure or an error status ends the session: without its upload it could
// only wait.
func (s *session) startStreamUpload(client *poolClient, request *http.Request) {
	go func() {
		// the server ends its answer once it has read the upload to its end
		defer s.writtenOnce.Do(func() { close(s.uploadWritten) })
		response, err := client.roundTrip(request)
		if err != nil {
			s.fail(E.Cause(err, "xhttp: upload"))
			return
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			s.fail(E.New("xhttp: upload: unexpected status ", response.Status))
			return
		}
		discardBody(response.Body)
	}()
}

func discardBody(body io.ReadCloser) {
	io.Copy(io.Discard, body)
	body.Close()
}

// setDownload sets the download body, or the error that stands for it, once;
// it reports whether this call did.
func (s *session) setDownload(body io.ReadCloser, err error) bool {
	var set bool
	s.downloadOnce.Do(func() {
		s.download = body
		s.downloadErr = err
		close(s.downloadReady)
		set = true
	})
	return set
}

// fail ends the session on the first failure of any of its requests: the other
// half is aborted, and both halves report this failure from then on.
func (s *session) fail(err error) {
	failure := &failureBox{hideHTTPError(err)}
	if !s.failure.CompareAndSwap(nil, failure) {
		failure = s.failure.Load()
	}
	s.setDownload(nil, failure.err)
	if s.streamBody != nil {
		s.streamBody.CloseWithError(failure.err)
	}
	if s.packetUpload != nil {
		s.packetUpload.interrupt(failure.err)
	}
	s.cancel()
}

// ioError turns an error of the HTTP machinery into the error the session
// reports: net.ErrClosed once closed here, the failure that ended the session,
// and otherwise an error that does not carry the HTTP/2 error types.
func (s *session) ioError(err error) error {
	if err == nil {
		return nil
	}
	if s.closed.Load() {
		return net.ErrClosed
	}
	if err == io.EOF {
		return err
	}
	if failure := s.failure.Load(); failure != nil {
		return failure.err
	}
	return hideHTTPError(err)
}

func (s *session) Read(b []byte) (int, error) {
	<-s.downloadReady
	if s.download == nil {
		return 0, s.ioError(s.downloadErr)
	}
	if len(s.pending) > 0 {
		n := copy(b, s.pending)
		s.pending = s.pending[n:]
		return n, nil
	}
	if s.pendingErr != nil {
		err := s.pendingErr
		s.pendingErr = nil
		return 0, s.ioError(err)
	}
	n, err := s.download.Read(b)
	if n > 0 && s.unanswered.Load() {
		s.unanswered.Store(false)
	}
	s.flowing = n == len(b)
	if err != nil {
		err = s.ioError(err)
	}
	return n, err
}

// probeSize is what an idle session holds while it waits for the server.
const probeSize = 512

// CreateReadWaiter lets the copy loop of sing wait for download data without
// its buffer: an idle session otherwise held a 32 KiB buffer for as long as
// the server stayed silent. The response body of HTTP/2 and 3 can't be peeked,
// so the waiter reads a small probe and hands it over before anything else;
// while data keeps filling whole buffers it reads straight away.
func (s *session) CreateReadWaiter() (N.ReadWaiter, bool) {
	return readwait.NewPeekWaiter(s, s.waitData), true
}

func (s *session) waitData() error {
	<-s.downloadReady
	if s.download == nil || len(s.pending) > 0 || s.pendingErr != nil || s.flowing {
		return nil
	}
	if s.probe == nil {
		s.probe = make([]byte, probeSize)
	}
	n, err := s.download.Read(s.probe)
	if n > 0 && s.unanswered.Load() {
		s.unanswered.Store(false)
	}
	s.pending = s.probe[:n]
	s.pendingErr = err
	s.flowing = n == len(s.probe)
	return nil
}

func (s *session) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if s.closed.Load() {
		return 0, net.ErrClosed
	}
	var (
		n   int
		err error
	)
	if !s.unanswered.Load() {
		s.unanswered.Store(true)
	}
	if s.packetUpload != nil {
		n, err = s.packetUpload.write(b)
	} else {
		n, err = s.streamUpload.Write(b)
	}
	if err != nil {
		err = s.ioError(err)
	}
	return n, err
}

// Close ends the session for its user at once, and the session itself once
// the data written before has left: sing-box closes a connection as soon as
// its source is done, and a request, a message or the last part of an upload
// written just before that must still reach the server, as it does with Xray,
// whose packet-up uploader and request bodies run to their end after a close.
func (s *session) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	// What the server has not answered since it was written may still be on
	// its way to the destination: the server takes the end of the download
	// for the end of the session. Such a session stays a moment after its
	// upload is sent, as an outbound of Xray does after the end of an upload
	// (a second, by Xray's default policy). A session whose last write was
	// answered, the usual end of an exchange, has nothing to wait for.
	unanswered := s.unanswered.Load()
	var sent <-chan struct{}
	switch {
	case s.failure.Load() != nil:
	case s.packetUpload != nil:
		if !s.packetUpload.idle() {
			sent = s.packetUpload.finish()
		} else if unanswered {
			sent = closedChannel
		}
	case s.streamUpload != nil:
		// the end of the request body: the HTTP client writes what it holds
		s.streamUpload.Close()
		sent = s.uploadWritten
	}
	if sent == nil {
		s.teardown()
		return nil
	}
	if !unanswered {
		select {
		case <-sent:
			s.teardown()
			return nil
		default:
		}
	}
	go func() {
		defer s.teardown()
		timer := time.NewTimer(closeLinger)
		defer timer.Stop()
		select {
		case <-sent:
		case <-s.ctx.Done():
			return
		case <-timer.C:
			return
		}
		if unanswered {
			timer.Reset(closeGrace)
			select {
			case <-timer.C:
			case <-s.ctx.Done():
			}
		}
	}()
	return nil
}

var closedChannel = func() chan struct{} {
	channel := make(chan struct{})
	close(channel)
	return channel
}()

// abandon ends a session nothing was written to, at once: a dial given up.
func (s *session) abandon() {
	s.closed.Store(true)
	s.teardown()
}

// teardown aborts the requests of the session and lets go of its connections.
func (s *session) teardown() {
	s.tearOnce.Do(s.doTeardown)
}

func (s *session) closeDownload() {
	if !s.setDownload(nil, net.ErrClosed) && s.download != nil {
		s.download.Close()
	}
}

func (s *session) doTeardown() {
	s.cancel()
	s.closeDownload()
	if s.streamBody != nil {
		s.streamBody.CloseWithError(net.ErrClosed)
	}
	if s.packetUpload != nil {
		s.packetUpload.interrupt(net.ErrClosed)
	}
	s.clientAccess.Lock()
	clients, counted := s.clients, s.counted
	s.clients, s.counted = nil, nil
	s.clientAccess.Unlock()
	for _, client := range counted {
		client.endSession()
	}
	for _, client := range clients {
		client.release()
	}
}

func (s *session) LocalAddr() net.Addr {
	if s.localAddr == nil {
		return M.Socksaddr{}
	}
	return s.localAddr
}

func (s *session) RemoteAddr() net.Addr {
	if s.remoteAddr == nil {
		return M.Socksaddr{}
	}
	return s.remoteAddr
}

// Deadlines are left to the caller's wrapper, as with the other HTTP based
// transports (NeedAdditionalReadDeadline).
func (s *session) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (s *session) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (s *session) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (s *session) NeedAdditionalReadDeadline() bool {
	return true
}

// transportError carries the text of an HTTP error without its type. An
// http2.StreamError read from a connection that an HTTP/2 client in turn reads
// (DoH, a rule-set download or a chained outbound over this transport) sticks
// in crypto/tls and makes that client's read loop spin on it forever.
type transportError struct {
	message string
}

func (e *transportError) Error() string {
	return e.message
}

func hideHTTPError(err error) error {
	if err == nil {
		return nil
	}
	err = baderror.WrapH2(err)
	if err == io.EOF || err == net.ErrClosed {
		return err
	}
	if _, isHidden := err.(*transportError); isHidden {
		return err
	}
	return &transportError{err.Error()}
}

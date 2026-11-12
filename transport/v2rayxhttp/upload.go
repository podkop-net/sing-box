package v2rayxhttp

import (
	"context"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// maxUploadBacklog bounds what a packet-up session buffers before its writes
// wait: Xray buffers up to sc_max_each_post_bytes, a megabyte by default, and
// on a router a megabyte per uploading connection adds up.
const maxUploadBacklog = 1024 * 1024

// A session has at most so many upload requests waiting for their answers, by
// count and by bytes (one request at the least): past that its writes wait.
// The server answers once it has queued the data, so with a destination that
// has stopped reading the answers stop too, while the requests would go on
// leaving, a megabyte each (lab: 52 unanswered requests, 73 MiB of heap, for
// one stalled upload). The count is for small requests, which are spaced
// sc_min_posts_interval_ms apart and so need many of them over a slow path.
const (
	maxUnansweredPosts = 32
	maxUnansweredBytes = 4 * 1024 * 1024
)

// uploadTimeout bounds one packet-up upload request on a connection that
// does not check on its server by itself.
const uploadTimeout = 60 * time.Second

// uploader sends the writes of a packet-up session as numbered requests. Writes
// are batched while a request is on its way, so that each request carries what
// accumulated meanwhile, up to the request size drawn for the session.
type uploader struct {
	session   *session
	client    *Client
	sessionID string
	maxSize   int
	backlog   int

	access   sync.Mutex
	pending  []byte
	err      error
	readable chan struct{}
	writable chan struct{}
	done     chan struct{}
	doneOnce sync.Once
	// closing is closed by finish: the session is closed, what is pending is
	// still sent. posts counts the requests on their way; finished is closed
	// when the last of them is over.
	closing      chan struct{}
	closingOnce  sync.Once
	posts        sync.WaitGroup
	inFlight     atomic.Int32
	inFlightSize atomic.Int64
	// answered is notified when a request is over.
	answered chan struct{}
	finished chan struct{}
	// postContext is the context of the requests: not that of the session,
	// see post. abortPosts cancels it.
	postContext context.Context
	abortPosts  context.CancelFunc

	// current is the client the uploads go through until it runs out of its
	// request budget; the uploader holds it (one running count).
	current *poolClient
}

func newUploader(s *session, client *Client, sessionID string, current *poolClient) *uploader {
	maxSize := int(client.up.maxEachPostBytes.rand())
	postContext, abortPosts := context.WithCancel(context.WithoutCancel(s.ctx))
	return &uploader{
		postContext: postContext,
		abortPosts:  abortPosts,
		answered:    make(chan struct{}, 1),
		session:     s,
		client:      client,
		sessionID:   sessionID,
		maxSize:     maxSize,
		backlog:     min(maxSize, maxUploadBacklog),
		readable:    make(chan struct{}, 1),
		writable:    make(chan struct{}, 1),
		done:        make(chan struct{}),
		closing:     make(chan struct{}),
		finished:    make(chan struct{}),
		current:     current,
	}
}

func notify(channel chan struct{}) {
	select {
	case channel <- struct{}{}:
	default:
	}
}

func (u *uploader) write(b []byte) (int, error) {
	var n int
	for len(b) > 0 {
		u.access.Lock()
		if u.err != nil {
			err := u.err
			u.access.Unlock()
			return n, err
		}
		space := u.backlog - len(u.pending)
		if space > 0 {
			take := min(space, len(b))
			u.pending = append(u.pending, b[:take]...)
			b = b[take:]
			n += take
			u.access.Unlock()
			notify(u.readable)
			continue
		}
		u.access.Unlock()
		select {
		case <-u.writable:
		case <-u.closing:
		case <-u.done:
		}
	}
	return n, nil
}

// idle tells that nothing written is waiting to be sent or to be answered.
func (u *uploader) idle() bool {
	u.access.Lock()
	defer u.access.Unlock()
	return len(u.pending) == 0 && u.inFlight.Load() == 0
}

// finish ends the uploader after a Close of its session: writes fail from then
// on, and the returned channel is closed once the data taken before has been
// sent and answered.
func (u *uploader) finish() <-chan struct{} {
	u.access.Lock()
	if u.err == nil {
		u.err = net.ErrClosed
	}
	u.access.Unlock()
	u.closingOnce.Do(func() { close(u.closing) })
	notify(u.writable)
	return u.finished
}

// interrupt stops the uploader: writes fail with err from then on.
func (u *uploader) interrupt(err error) {
	u.access.Lock()
	if u.err == nil {
		u.err = err
	}
	u.pending = nil
	u.access.Unlock()
	u.doneOnce.Do(func() { close(u.done) })
	// The session is over, failed or closed and past its linger: its requests
	// still without an answer end with it, where that is safe (see post).
	if u.client.upPool.watched {
		u.abortPosts()
	}
}

// overBudget tells that no more requests may leave before one is answered.
func (u *uploader) overBudget() bool {
	count := u.inFlight.Load()
	return count > 0 && (count >= maxUnansweredPosts || u.inFlightSize.Load() >= maxUnansweredBytes)
}

func (u *uploader) run() {
	defer func() {
		if u.current != nil {
			u.current.release()
		}
		u.posts.Wait()
		close(u.finished)
	}()
	var (
		seq      int64
		lastPost time.Time
		closing  bool
	)
	for {
		if !closing {
			select {
			case <-u.readable:
			case <-u.closing:
				closing = true
			case <-u.done:
				return
			}
		}
		// What is pending stays there, and fills, while too many requests wait
		// for their answers: the writes of the session wait in turn.
		for u.overBudget() {
			select {
			case <-u.answered:
			case <-u.done:
				return
			}
		}
		u.access.Lock()
		// The backlog never exceeds the request size, so all of it fits in one
		// request and is handed over without a copy.
		data := u.pending
		u.pending = nil
		if len(data) > 0 {
			// counted from here on, under the lock: idle must not see the gap
			// between the backlog and the request
			u.inFlight.Add(1)
			u.inFlightSize.Add(int64(len(data)))
		}
		u.access.Unlock()
		if len(data) == 0 {
			if closing {
				return
			}
			continue
		}
		notify(u.writable)
		// As with Xray, a range that starts at zero means no waiting at all.
		if interval := u.client.up.minPostsIntervalMs.rand(); interval > 0 && u.client.up.minPostsIntervalMs.from > 0 {
			wait := time.Duration(interval)*time.Millisecond - time.Since(lastPost)
			if wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case <-timer.C:
				case <-u.done:
					timer.Stop()
					u.inFlight.Add(-1)
					u.inFlightSize.Add(-int64(len(data)))
					return
				}
			}
		}
		lastPost = time.Now()
		client, err := u.nextClient()
		if err != nil {
			u.inFlight.Add(-1)
			u.inFlightSize.Add(-int64(len(data)))
			u.session.fail(E.Cause(err, "xhttp: upload"))
			return
		}
		wrote := make(chan struct{})
		u.posts.Add(1)
		go u.post(client, strconv.FormatInt(seq, 10), data, wrote)
		seq++
		// The next request goes once this one is written, not answered.
		select {
		case <-wrote:
		case <-u.done:
			return
		}
	}
}

// nextClient returns the client for the next upload with one running count
// for that upload: the current one while it has request budget, otherwise a
// new one from the pool, which becomes current.
func (u *uploader) nextClient() (*poolClient, error) {
	if u.current != nil && u.current.usable() {
		u.current.acquire()
		return u.current, nil
	}
	client, err := u.client.upPool.get(false)
	if err != nil {
		// No new connection now (the pool backs off): a current one that is
		// only out of its budget still works.
		if u.current != nil && !u.current.broken.Load() {
			u.current.acquire()
			return u.current, nil
		}
		return nil, err
	}
	if u.current != nil {
		u.current.release()
	}
	client.acquire()
	u.current = client
	return client, nil
}

func (u *uploader) post(client *poolClient, seq string, data []byte, wrote chan struct{}) {
	defer u.posts.Done()
	defer func() {
		u.inFlightSize.Add(-int64(len(data)))
		u.inFlight.Add(-1)
		notify(u.answered)
	}()
	defer client.release()
	var once sync.Once
	written := func() { once.Do(func() { close(wrote) }) }
	defer written()
	// An upload is not cancelled with its session, as with Xray: net/http hands
	// a connection back to its pool before it delivers a response without a
	// body, and a request cancelled in between closes that connection under the
	// next request, which then fails with "context canceled" (HTTP/1.1: 1 to 3
	// uploads in 4000 when sessions closed at once).
	//
	// The server answers an upload once it has queued the data, and with its
	// queue full that is once the destination has read some: an answer may
	// take as long as the destination stays busy, and a time limit on it cut
	// off a slow upload that a TCP connection, and Xray, carry through (lab:
	// a destination idle for four minutes got 4 of 60 MB). So there is none
	// where the connection itself notices a server that went silent. Where
	// nothing does (HTTP/1.1, HTTP/2 with its pings turned off) the limit
	// stays: the wait, and the data written at 64 kbit/s.
	//
	// On the watched connections a request is a stream of its own, and ending
	// it harms nothing else: there the requests of a session that is over
	// (failed, or closed and past its linger) are cancelled, so that one the
	// server never answers does not hold its data and its connection.
	ctx := u.postContext
	if !u.client.upPool.watched {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, uploadTimeout+time.Duration(len(data))*time.Second/(8*1024))
		defer cancel()
	}
	ctx = context.WithValue(ctx, packetRequestKey{}, true)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) { written() },
	})
	request := u.client.up.newPacketRequest(ctx, u.client.upScheme, u.sessionID, seq, data)
	response, err := client.roundTrip(request)
	if err != nil {
		if headersTooLarge(err) {
			err = E.Cause(err, tooLargeHint)
		}
		u.session.fail(E.Cause(err, "xhttp: upload"))
		return
	}
	discardBody(response.Body)
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusRequestHeaderFieldsTooLarge, http.StatusRequestEntityTooLarge:
		u.session.fail(E.New("xhttp: upload: ", tooLargeHint, ": unexpected status ", response.Status))
	default:
		u.session.fail(E.New("xhttp: upload: unexpected status ", response.Status))
	}
}

// tooLargeHint names the setting behind a request the server (or a proxy in
// front of it) refused for its size. With the data in headers or cookies the
// limit is that of the request headers: 8 KiB with Xray's defaults, which
// about 4 KiB of data fit in.
const tooLargeHint = "the request is larger than the server takes, lower sc_max_each_post_bytes"

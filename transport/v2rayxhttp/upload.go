package v2rayxhttp

import (
	"context"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// maxUploadBacklog bounds what a packet-up session buffers before its writes
// wait: Xray buffers up to sc_max_each_post_bytes, a megabyte by default, and
// on a router a megabyte per uploading connection adds up.
const maxUploadBacklog = 1024 * 1024

// uploadTimeout bounds one packet-up upload request.
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

	// current is the client the uploads go through until it runs out of its
	// request budget; the uploader holds it (one running count).
	current *poolClient
}

func newUploader(s *session, client *Client, sessionID string, current *poolClient) *uploader {
	maxSize := int(client.up.maxEachPostBytes.rand())
	return &uploader{
		session:   s,
		client:    client,
		sessionID: sessionID,
		maxSize:   maxSize,
		backlog:   min(maxSize, maxUploadBacklog),
		readable:  make(chan struct{}, 1),
		writable:  make(chan struct{}, 1),
		done:      make(chan struct{}),
		current:   current,
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
		case <-u.done:
		}
	}
	return n, nil
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
}

func (u *uploader) run() {
	defer func() {
		if u.current != nil {
			u.current.release()
		}
	}()
	var (
		seq      int64
		lastPost time.Time
	)
	for {
		select {
		case <-u.readable:
		case <-u.done:
			return
		}
		u.access.Lock()
		// The backlog never exceeds the request size, so all of it fits in one
		// request and is handed over without a copy.
		data := u.pending
		u.pending = nil
		u.access.Unlock()
		if len(data) == 0 {
			continue
		}
		notify(u.writable)
		if interval := u.client.up.minPostsIntervalMs.rand(); interval > 0 {
			wait := time.Duration(interval)*time.Millisecond - time.Since(lastPost)
			if wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case <-timer.C:
				case <-u.done:
					timer.Stop()
					return
				}
			}
		}
		lastPost = time.Now()
		client, err := u.nextClient()
		if err != nil {
			u.session.fail(E.Cause(err, "xhttp: upload"))
			return
		}
		wrote := make(chan struct{})
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
	defer client.release()
	var once sync.Once
	written := func() { once.Do(func() { close(wrote) }) }
	defer written()
	// An upload is not cancelled with its session, as with Xray: net/http hands
	// a connection back to its pool before it delivers a response without a
	// body, and a request cancelled in between closes that connection under the
	// next request, which then fails with "context canceled" (HTTP/1.1: 1 to 3
	// uploads in 4000 when sessions closed at once). The timeout bounds an
	// upload to a server that went silent.
	// It allows for writing the data at 64 kbit/s on top of the wait.
	timeout := uploadTimeout + time.Duration(len(data))*time.Second/(8*1024)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(u.session.ctx), timeout)
	defer cancel()
	ctx = context.WithValue(ctx, packetRequestKey{}, true)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) { written() },
	})
	request := u.client.up.newPacketRequest(ctx, u.client.upScheme, u.sessionID, seq, data)
	response, err := client.roundTrip(request)
	if err != nil {
		u.session.fail(E.Cause(err, "xhttp: upload"))
		return
	}
	discardBody(response.Body)
	if response.StatusCode != http.StatusOK {
		u.session.fail(E.New("xhttp: upload: unexpected status ", response.Status))
	}
}

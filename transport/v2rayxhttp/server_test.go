package v2rayxhttp

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testServer is an XHTTP server for the tests, after Xray's hub.go: it reads the
// session ID, the sequence number and packet-up data where config places them,
// checks the padding, puts packet-up uploads back in order and echoes every
// session's upload on its download.
type testServer struct {
	t      *testing.T
	config *requestConfig
	server *httptest.Server

	// holdDownload makes a download wait for the first upload of its session,
	// as an Xray server behind a CDN effectively does.
	holdDownload   bool
	downloadStatus int
	// endlessErrorBody makes the body of an error answer never end.
	endlessErrorBody bool
	uploadStatus     int
	// maxPacket makes the server refuse larger packets as a proxy with a
	// limit on request headers does, with status 431.
	maxPacket int
	// abortUploads resets every upload request (RST_STREAM on HTTP/2).
	abortUploads bool

	access   sync.Mutex
	sessions map[string]*testSession
	requests map[string]int
	remotes  map[string]struct{}
}

type testSession struct {
	access    sync.Mutex
	nextSeq   int64
	buffered  map[int64][]byte
	echo      chan []byte
	firstData chan struct{}
	firstOnce sync.Once
}

func newTestServer(t *testing.T, config *requestConfig, mode string) *testServer {
	s := &testServer{
		t:        t,
		config:   config,
		sessions: make(map[string]*testSession),
		requests: make(map[string]int),
	}
	s.server = httptest.NewUnstartedServer(http.HandlerFunc(s.serveHTTP))
	switch mode {
	case "h2":
		s.server.EnableHTTP2 = true
		s.server.StartTLS()
	case "h2-8k":
		// the header limit of an Xray server with its defaults
		s.server.Config.MaxHeaderBytes = 8192
		s.server.EnableHTTP2 = true
		s.server.StartTLS()
	case "h1-tls":
		s.server.StartTLS()
	default:
		s.server.Start()
	}
	t.Cleanup(s.server.Close)
	return s
}

func (s *testServer) session(id string) *testSession {
	s.access.Lock()
	defer s.access.Unlock()
	session := s.sessions[id]
	if session == nil {
		session = &testSession{
			buffered:  make(map[int64][]byte),
			echo:      make(chan []byte, 1024),
			firstData: make(chan struct{}),
		}
		s.sessions[id] = session
	}
	return session
}

func (s *testServer) count(kind string) {
	s.access.Lock()
	s.requests[kind]++
	s.access.Unlock()
}

// connections is the number of client connections requests came on.
func (s *testServer) connections() int {
	s.access.Lock()
	defer s.access.Unlock()
	return len(s.remotes)
}

func (s *testServer) requestCount(kind string) int {
	s.access.Lock()
	defer s.access.Unlock()
	return s.requests[kind]
}

func (ts *testSession) push(data []byte) {
	ts.firstOnce.Do(func() { close(ts.firstData) })
	if len(data) > 0 {
		ts.echo <- data
	}
}

// pushPacket queues one packet-up upload and releases those now in order.
func (ts *testSession) pushPacket(seq int64, data []byte) {
	ts.access.Lock()
	ts.buffered[seq] = data
	var ready [][]byte
	for {
		next, loaded := ts.buffered[ts.nextSeq]
		if !loaded {
			break
		}
		delete(ts.buffered, ts.nextSeq)
		ts.nextSeq++
		ready = append(ready, next)
	}
	ts.access.Unlock()
	for _, data := range ready {
		ts.push(data)
	}
}

func (s *testServer) checkPadding(r *http.Request) bool {
	c := s.config
	var padding string
	if !c.paddingObfsMode {
		referer, err := url.Parse(r.Header.Get("Referer"))
		if err != nil {
			return false
		}
		padding = referer.Query().Get("x_padding")
	} else {
		switch c.paddingPlacement {
		case placementHeader:
			padding = r.Header.Get(c.paddingHeader)
		case placementQueryInHeader:
			value, err := url.Parse(r.Header.Get(c.paddingHeader))
			if err != nil {
				return false
			}
			padding = value.Query().Get(c.paddingKey)
		case placementCookie:
			cookie, err := r.Cookie(c.paddingKey)
			if err != nil {
				return false
			}
			padding = cookie.Value
		case placementQuery:
			padding = r.URL.Query().Get(c.paddingKey)
		}
	}
	if c.paddingObfsMode && c.paddingMethod == paddingMethodTokenish {
		// tokenish is sized by its Huffman length, within 2.
		return len(padding) > 0
	}
	return len(padding) >= int(c.paddingBytes.from) && len(padding) <= int(c.paddingBytes.to)
}

// meta reads the session ID and the sequence number as Xray's
// ExtractMetaFromRequest does.
func (s *testServer) meta(r *http.Request) (string, string) {
	c := s.config
	var parts []string
	if c.sessionPlacement == placementPath || c.seqPlacement == placementPath {
		parts = strings.Split(strings.TrimPrefix(r.URL.Path, c.normalizedPath()), "/")
	}
	index := 0
	read := func(placement string, key string) string {
		switch placement {
		case placementPath:
			if index < len(parts) {
				index++
				return parts[index-1]
			}
		case placementQuery:
			return r.URL.Query().Get(key)
		case placementHeader:
			return r.Header.Get(key)
		case placementCookie:
			if cookie, err := r.Cookie(key); err == nil {
				return cookie.Value
			}
		}
		return ""
	}
	sessionID := read(c.sessionPlacement, c.sessionKey)
	seq := read(c.seqPlacement, c.seqKey)
	return sessionID, seq
}

func (s *testServer) packetData(r *http.Request) ([]byte, error) {
	c := s.config
	switch c.uplinkDataPlacement {
	case placementHeader:
		var encoded strings.Builder
		for i := 0; ; i++ {
			value := r.Header.Get(c.uplinkDataKey + "-" + strconv.Itoa(i))
			if value == "" {
				break
			}
			encoded.WriteString(value)
		}
		return base64.RawURLEncoding.DecodeString(encoded.String())
	case placementCookie:
		var encoded strings.Builder
		for i := 0; ; i++ {
			cookie, err := r.Cookie(c.uplinkDataKey + "_" + strconv.Itoa(i))
			if err != nil {
				break
			}
			encoded.WriteString(cookie.Value)
		}
		return base64.RawURLEncoding.DecodeString(encoded.String())
	default:
		return io.ReadAll(r.Body)
	}
}

func (s *testServer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	s.access.Lock()
	if s.remotes == nil {
		s.remotes = make(map[string]struct{})
	}
	s.remotes[r.RemoteAddr] = struct{}{}
	s.access.Unlock()
	if !strings.HasPrefix(r.URL.Path, s.config.normalizedPath()) {
		s.count("not-found")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if !s.checkPadding(r) {
		s.count("bad-padding")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sessionID, seq := s.meta(r)
	isUpload := r.Method != http.MethodGet || seq != ""
	switch {
	case sessionID == "":
		s.count("stream-one")
		s.serveStreamOne(w, r)
	case !isUpload:
		s.count("download")
		s.serveDownload(w, r, s.session(sessionID))
	case seq != "":
		s.count("packet")
		if s.abortUploads {
			panic(http.ErrAbortHandler)
		}
		if s.uploadStatus != 0 {
			w.WriteHeader(s.uploadStatus)
			return
		}
		number, err := strconv.ParseInt(seq, 10, 64)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		data, err := s.packetData(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if s.maxPacket > 0 && len(data) > s.maxPacket {
			w.WriteHeader(http.StatusRequestHeaderFieldsTooLarge)
			return
		}
		s.session(sessionID).pushPacket(number, data)
		w.WriteHeader(http.StatusOK)
	default:
		s.count("stream-up")
		if s.abortUploads {
			panic(http.ErrAbortHandler)
		}
		if s.uploadStatus != 0 {
			w.WriteHeader(s.uploadStatus)
			return
		}
		session := s.session(sessionID)
		http.NewResponseController(w).EnableFullDuplex()
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		buffer := make([]byte, 32*1024)
		for {
			n, err := r.Body.Read(buffer)
			if n > 0 {
				session.push(append([]byte(nil), buffer[:n]...))
			}
			if err != nil {
				return
			}
		}
	}
}

func (s *testServer) serveDownload(w http.ResponseWriter, r *http.Request, session *testSession) {
	if s.holdDownload {
		select {
		case <-session.firstData:
		case <-r.Context().Done():
			return
		}
	}
	if s.downloadStatus != 0 {
		w.WriteHeader(s.downloadStatus)
		for s.endlessErrorBody && r.Context().Err() == nil {
			w.Write([]byte("error page "))
			w.(http.Flusher).Flush()
			time.Sleep(10 * time.Millisecond)
		}
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
	for {
		select {
		case data := <-session.echo:
			if _, err := w.Write(data); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *testServer) serveStreamOne(w http.ResponseWriter, r *http.Request) {
	if s.downloadStatus != 0 {
		w.WriteHeader(s.downloadStatus)
		return
	}
	http.NewResponseController(w).EnableFullDuplex()
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
	buffer := make([]byte, 32*1024)
	for {
		n, err := r.Body.Read(buffer)
		if n > 0 {
			if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
		if err != nil {
			return
		}
	}
}

package urltest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestDownloadTest(t *testing.T) {
	var sawRange, sawEncoding bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawRange = r.Header.Get("Range") == "bytes=0-"+strconv.Itoa(DownloadTestSize-1)
		sawEncoding = r.Header.Get("Accept-Encoding") != ""
		switch r.URL.Path {
		case "/full":
			w.Header().Set("Content-Length", strconv.Itoa(DownloadTestSize))
			w.Write(make([]byte, DownloadTestSize))
		case "/big": // a server that ignores the range: only the size is read
			w.Header().Set("Content-Length", strconv.Itoa(4*DownloadTestSize))
			w.Write(make([]byte, 4*DownloadTestSize))
		case "/short":
			w.Header().Set("Content-Length", "1000")
			w.Write(make([]byte, 1000))
		case "/chunked-short": // a short body of unknown length cannot be told from a cut one
			w.(http.Flusher).Flush() // chunked: the server would otherwise count the body itself
			w.Write(make([]byte, 1000))
		case "/stall":
			w.Header().Set("Content-Length", strconv.Itoa(DownloadTestSize))
			w.Write(make([]byte, 16384))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case "/close":
			w.Header().Set("Content-Length", strconv.Itoa(DownloadTestSize))
			w.Write(make([]byte, 16384))
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	for _, testCase := range []struct {
		path     string
		received int64
		ok       bool
		stopped  bool
	}{
		{"/full", DownloadTestSize, true, false},
		{"/big", DownloadTestSize, true, false},
		{"/short", 1000, false, false},         // the URL cannot show a freeze: not the member's fault
		{"/chunked-short", 1000, false, false}, // the same, as far as can be told
		{"/stall", 16384, false, true},         // the body stopped: the link
		{"/close", 16384, false, true},
		{"/missing", 0, false, false},
	} {
		t.Run(testCase.path, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			received, _, err := DownloadTest(ctx, server.URL+testCase.path, N.SystemDialer)
			require.Equal(t, testCase.ok, err == nil, "%v", err)
			require.Equal(t, testCase.stopped, errors.Is(err, ErrDownloadStopped), "%v", err)
			require.Equal(t, testCase.received, received)
			require.True(t, sawRange, "no range asked")
			require.False(t, sawEncoding, "compression accepted")
		})
	}
}

package urltest

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// DownloadTestSize is how much of the body a download test reads at most: 64 KiB. Connections
// to foreign servers are reported frozen after 16-20 KB, or 25 packets, in either direction
// (net4people/bbs#490); 64 KiB is 45 full-size segments, past the largest reported threshold
// three times over, and what the default test URL asks the server for.
const DownloadTestSize = 64 * 1024

// ErrDownloadStopped is the failure of a download test that says something about the link:
// the body began and then stopped, by a stall or a close, before the size arrived. Any other
// failure (a status, a TLS error, no body at all, a body the server announced shorter than
// the size) is the test's own and proves nothing about the member.
var ErrDownloadStopped = E.New("download stopped")

// DownloadTest fetches link through detour and reads DownloadTestSize bytes of the body. It
// returns the bytes received and the time they took; the error is ErrDownloadStopped when
// the body stopped on the way (see there), another error when the test could not run.
func DownloadTest(ctx context.Context, link string, detour N.Dialer) (received int64, elapsed time.Duration, err error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return
	}
	hostname := linkURL.Hostname()
	port := linkURL.Port()
	if port == "" {
		switch linkURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	start := time.Now()
	instance, err := detour.DialContext(ctx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
	if err != nil {
		return
	}
	defer instance.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return
	}
	// a server that honours ranges sends no more than is read (the default one does not: its
	// bytes= query sets the size); one that does not is cut off by the read itself. With a
	// range Go asks for no compression either; the flag below says so explicitly.
	req.Header.Set("Range", "bytes=0-"+strconv.Itoa(DownloadTestSize-1))
	client := probeClient(ctx, instance)
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return 0, 0, E.New("HTTP ", resp.StatusCode)
	}
	received, err = io.CopyN(io.Discard, resp.Body, DownloadTestSize)
	elapsed = time.Since(start)
	switch {
	case err == nil:
		return received, elapsed, nil
	case received == 0:
		return 0, elapsed, E.Cause(err, "no body")
	case errors.Is(err, io.EOF) && (resp.ContentLength < 0 || received == resp.ContentLength):
		// the whole body, as far as can be told, and it is shorter than the size: the URL
		// cannot show what the test is for
		return received, elapsed, E.New("the body is ", received, " bytes, ", DownloadTestSize, " needed")
	default:
		return received, elapsed, E.Cause(ErrDownloadStopped, "after ", received, " bytes")
	}
}

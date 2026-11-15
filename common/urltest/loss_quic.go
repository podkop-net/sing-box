package urltest

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/probesock"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

// The loss probe of a member over QUIC (podkop-engine).
//
// The connections of a Hysteria2 or TUIC member are streams of one QUIC connection: the TCP
// probe has no connection of its own to count (ErrLossNotOwnConnection). QUIC numbers every
// packet, so the member tells how many of the server's packets came and how many numbers did not
// (adapter.QUICStatsOutbound). LossProbeQUIC downloads what LossProbe does, a window at a time:
// probesock.Window bytes, the next window asked for when it has come in full, so the server sends
// no more in a round trip than the TCP probe's window lets it, whatever its
// congestion control (Brutal sends at a set rate and does not slow down on loss, and the stream
// windows of Hysteria2 are megabytes: one request for the whole body would be sent at once). The
// sample is the difference of the counts across the download. What else the connection carried
// meanwhile (the member in use) is in it too: the sample then weighs as many packets as the probe
// brought itself, at the share the connection lost, as the sample of LossProbe is the segments of
// its own connection. A window is a range of the link; a link with a "bytes" parameter (the
// default loss URL, speed.cloudflare.com/__down, serves no ranges: it answers a range with the
// whole body) is asked for a body of that many bytes instead.

// QUICCounter tells the counts of a QUIC connection (adapter.QUICStatsOutbound).
type QUICCounter interface {
	QUICStats() (adapter.QUICStats, bool)
}

// errStillComing tells a window cut while its body still came (the time limit, the end of the
// group): the probe is counted as far as it came, as LossProbe does.
var errStillComing = E.New("cut while the body came")

// quicReorderWait is how long after the last window the counts are read: QUIC takes a packet for
// lost when it is 9/8 of the smoothed RTT late (RFC 9002, kTimeThreshold), so a packet that comes
// out of order comes within that and takes its gap back.
func quicReorderWait(stats adapter.QUICStats) time.Duration {
	return min(stats.SmoothedRTT*9/8, time.Second)
}

// quicPacketBytes is fewer bytes of a body than a packet of a Hysteria2 or TUIC server carries (up
// to its datagrams of 1200 to 1452 bytes): body/quicPacketBytes is more packets than a body takes.
const quicPacketBytes = 1000

// quicProbePackets is how many packets a probe that brought received bytes in windows windows
// takes at most: the body, and for each window a response header and an acknowledgment or two.
func quicProbePackets(received int64, windows int) uint64 {
	return uint64(received/quicPacketBytes) + 4*uint64(windows) + 16
}

// quicWait waits d, unless ctx is canceled (the group was closed): a probe cut by its own time
// limit still waits, for the packets that come late.
func quicWait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			<-timer.C
			return nil
		}
		return ctx.Err()
	}
}

// LossProbeQUIC downloads size bytes of link through detour, a window at a time, and returns what
// the QUIC connection of counter counted meanwhile. Its errors are LossProbe's, and one wrapping
// ErrLossNotCounted when the member had no QUIC connection, the connection was closed or replaced
// during the probe, or the UDP receive buffers of the system dropped datagrams meanwhile (the count
// would put them on the path).
func LossProbeQUIC(ctx context.Context, link string, size int64, detour N.Dialer, counter QUICCounter) (LossSample, error) {
	var sample LossSample
	linkURL, err := url.Parse(link)
	if err != nil {
		return sample, err
	}
	port := linkURL.Port()
	if port == "" {
		switch linkURL.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	destination := M.ParseSocksaddrHostPortStr(linkURL.Hostname(), port)
	byParameter := linkURL.Query().Has("bytes")
	ctx = ContextWithTest(ctx)
	start := time.Now()
	// a stream held open across the probe, dialed before the first count: a member whose connection
	// was idle dials it now, and the connection stays while the HTTP connections of the probe close
	// and come again. A member no group uses closes its connection with its last stream: a window
	// cut by the time limit, or an HTTP connection not kept between windows, closed it before it
	// was counted. Closed at the end, after the client's, it leaves the member to close the
	// connection as it would have.
	anchor, err := detour.DialContext(ctx, "tcp", destination)
	if err != nil {
		return sample, err
	}
	defer anchor.Close()
	before, active := counter.QUICStats()
	if !active {
		return sample, E.Cause(ErrLossNotCounted, "no QUIC connection")
	}
	dropsBefore, dropsKnown := udpReceiveDrops()
	client := quicProbeClient(ctx, detour, destination)
	defer client.CloseIdleConnections()
	var received int64
	var probeErr error
	windows := 0
	for received < size {
		end := min(received+probesock.Window, size) - 1
		got, err := quicProbeWindow(ctx, client, linkURL, byParameter, received, end)
		received += got
		windows++
		if err != nil {
			probeErr = err
			break
		}
	}
	sample.Elapsed = time.Since(start)
	sample.Received = received
	switch {
	case probeErr == nil, errors.Is(probeErr, io.EOF):
		// io.EOF: the whole body, shorter than asked, counted as it is
	case received == 0:
		return sample, E.Cause(probeErr, "no body")
	case errors.Is(probeErr, errStillComing):
		// cut while it came: counted as far as it came
	default:
		return sample, probeErr
	}
	// the wait for what comes out of order, by the RTT the connection has now (a connection of
	// 0-RTT may have had none before)
	now, active := counter.QUICStats()
	if !active || now.Connection != before.Connection {
		return sample, E.Cause(ErrLossNotCounted, "the QUIC connection was closed or replaced during the probe")
	}
	if err := quicWait(ctx, quicReorderWait(now)); err != nil {
		return sample, err
	}
	after, active := counter.QUICStats()
	if !active || after.Connection != before.Connection {
		return sample, E.Cause(ErrLossNotCounted, "the QUIC connection was closed or replaced during the probe")
	}
	if dropsKnown {
		if dropsAfter, known := udpReceiveDrops(); known && dropsAfter > dropsBefore {
			return sample, E.Cause(ErrLossNotCounted, "the UDP receive buffers of the system dropped ", dropsAfter-dropsBefore, " datagrams")
		}
	}
	came := after.PeerPacketsReceived - before.PeerPacketsReceived
	var lost uint64
	if after.PeerPacketsMissing > before.PeerPacketsMissing {
		lost = after.PeerPacketsMissing - before.PeerPacketsMissing
	}
	// the connection carried more than the probe (the member in use): as many packets as the probe
	// took, at the share the connection lost, or one busy probe would outweigh the rest of a window
	// of hours (lossMinSegments of the group)
	if own := quicProbePackets(received, windows); came+lost > own {
		share := (lost*own + (came+lost)/2) / (came + lost)
		came, lost = own-share, share
	}
	sample.At = time.Now()
	sample.Segments = int(came + lost)
	sample.Lost = int(lost)
	sample.RTT = after.MinRTT
	return sample, nil
}

// quicProbeWindow downloads the window from start to end of link (a range, or with byParameter a
// body of that many bytes) and returns how many bytes came: io.EOF tells a body shorter than asked
// (the whole of what there is), errStillComing a body cut while it came, ErrDownloadStopped one
// that brought nothing for lossStall before it ended, ErrLossNoWindows a link that serves no
// ranges.
func quicProbeWindow(ctx context.Context, client *http.Client, link *url.URL, byParameter bool, start, end int64) (int64, error) {
	target := *link
	if byParameter {
		query := target.Query()
		query.Set("bytes", strconv.FormatInt(end-start+1, 10))
		target.RawQuery = query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return 0, err
	}
	if !byParameter {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(start, 10)+"-"+strconv.FormatInt(end, 10))
	}
	asked := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil && time.Since(asked) < lossStall {
			return 0, errors.Join(errStillComing, err)
		}
		return 0, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusPartialContent && !byParameter, resp.StatusCode == http.StatusOK && byParameter:
	case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable && !byParameter && start > 0:
		// the file ended where the window before did: the whole of it came
		return 0, io.EOF
	case resp.StatusCode == http.StatusOK:
		// no ranges: the whole body comes at once, past the window
		return 0, errors.Join(ErrLossNotCounted, ErrLossNoWindows)
	default:
		return 0, E.New("HTTP ", resp.StatusCode)
	}
	want := end - start + 1
	body := &progressReader{Reader: resp.Body, last: time.Now()}
	got, err := io.CopyN(io.Discard, body, want)
	switch {
	case err == nil:
		return got, nil
	case errors.Is(err, io.EOF):
		return got, io.EOF
	case time.Since(body.last) < lossStall:
		return got, errors.Join(errStillComing, err)
	default:
		return got, E.Cause(errors.Join(ErrDownloadStopped, err), "after ", got, " bytes")
	}
}

// quicProbeClient makes the HTTP client of a QUIC probe: its connections are streams dialed through
// detour (over the same QUIC connection). One connection at a time, no redirects, no compression
// asked for, as probeClient.
func quicProbeClient(ctx context.Context, detour N.Dialer, destination M.Socksaddr) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				return detour.DialContext(dialCtx, "tcp", destination)
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
			DisableCompression: true,
			MaxConnsPerHost:    1,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: lossClientTimeout,
	}
}

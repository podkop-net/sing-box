package urltest

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/common/probesock"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// The loss probe (podkop-engine).
//
// A URL test cannot see loss: a few hundred bytes cross a lossy path as fast as a clean one.
// A loss probe downloads LossProbeSmall or LossProbeLarge bytes through a server over a TCP
// connection of its own with a small receive window, and counts the segments of that
// connection that were lost on the way (probesock). On the stand a single probe of 1 MB
// called no clean path lossy, found a loss of 2 % or more every time and one of 1 % eight or
// nine times in ten; one of 256 KB is too short for a decision of its own, and the probes of
// a server are summed over windows of hours (LossOfWindow).

const (
	// LossProbeSmall is the size of the periodic probe of a server.
	LossProbeSmall = 256 << 10
	// LossProbeLarge is the size of the probe of a server before a switch to it.
	LossProbeLarge = 1 << 20
	// LossProbeTimeout bounds a probe: a megabyte at a window of 16 KB over a path of 300 ms is
	// some twenty seconds.
	LossProbeTimeout = 30 * time.Second
)

// ErrLossNotCounted is the failure of a probe that downloaded but could not count: the
// connection was not its own (a multiplexed transport, QUIC), or the capture could not
// keep up. It says nothing about the server.
var ErrLossNotCounted = E.New("loss not counted")

// ErrLossNotOwnConnection wraps ErrLossNotCounted when the probe had no TCP connection of its
// own (a multiplexed transport, QUIC): probing the member again would not count either.
var ErrLossNotOwnConnection = E.New("the probe had no connection of its own")

// lossStall is how long a body may bring nothing before the probe calls it stopped: a slow
// path that keeps bringing data is counted as far as it came, not failed. A variable for the
// tests, as lossClientTimeout.
var lossStall = 5 * time.Second

// lossClientTimeout bounds the request of a probe.
var lossClientTimeout = LossProbeTimeout

// progressReader notes when the last bytes came.
type progressReader struct {
	io.Reader
	last time.Time
}

func (r *progressReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		r.last = time.Now()
	}
	return n, err
}

// LossSample is what one loss probe counted.
type LossSample struct {
	At        time.Time
	Received  int64 // bytes of the body
	Elapsed   time.Duration
	Segments  int
	Lost      int
	Reordered int64 // bytes that came out of order and were not lost
	RTT       time.Duration
}

// LossProbe downloads size bytes of link through detour over a probe connection and returns
// what its packets showed. A body cut by the time limit while it still came (a slow path: a
// megabyte at the window of the probe takes some 50 round trips) is counted as far as it
// came. An error wrapping ErrLossNotCounted tells a download that went but could not be
// counted (ErrLossNotOwnConnection: and never will be); one wrapping ErrDownloadStopped, a body
// that began and then brought nothing for lossStall (the member's failure, as in the
// download test); another error, a probe that could not run (the URL answered with a status,
// the dial failed), which proves nothing about the member.
func LossProbe(ctx context.Context, link string, size int64, detour N.Dialer) (LossSample, error) {
	var sample LossSample
	linkURL, err := url.Parse(link)
	if err != nil {
		return sample, err
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
	probeCtx, socket := probesock.With(ctx, probesock.Window)
	defer socket.Close()
	start := time.Now()
	instance, err := detour.DialContext(probeCtx, "tcp", M.ParseSocksaddrHostPortStr(hostname, port))
	if err != nil {
		return sample, err
	}
	defer instance.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return sample, err
	}
	req.Header.Set("Range", "bytes=0-"+strconv.FormatInt(size-1, 10))
	client := probeClient(ctx, instance)
	client.Timeout = lossClientTimeout
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return sample, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return sample, E.New("HTTP ", resp.StatusCode)
	}
	body := &progressReader{Reader: resp.Body, last: time.Now()}
	received, err := io.CopyN(io.Discard, body, size)
	sample.Elapsed = time.Since(start)
	sample.Received = received
	if err != nil {
		switch {
		case received == 0:
			return sample, E.Cause(err, "no body")
		case errors.Is(err, io.EOF):
			// the whole body, shorter than asked: counted as it is
		case time.Since(body.last) < lossStall:
			// cut by the time limit (or the end of the group) while it came: counted as far
			// as it came
		default:
			return sample, E.Cause(errors.Join(ErrDownloadStopped, err), "after ", received, " bytes")
		}
	}
	result, err := socket.Finish()
	if errors.Is(err, probesock.ErrNoOwnConnection) {
		return sample, E.Cause(errors.Join(ErrLossNotCounted, ErrLossNotOwnConnection), err)
	}
	if err != nil {
		return sample, E.Cause(ErrLossNotCounted, err)
	}
	switch {
	case result.Dropped > 0:
		return sample, E.Cause(ErrLossNotCounted, "the capture dropped ", result.Dropped, " packets")
	case result.Bytes < received:
		// the body came over another connection: the one counted was not the probe's
		return sample, E.Cause(ErrLossNotCounted, "the connection counted carried ", result.Bytes, " bytes of ", received)
	}
	sample.At = time.Now()
	sample.Segments = result.Segments
	sample.Lost = result.Lost
	sample.Reordered = result.ReorderBytes
	sample.RTT = result.RTT
	return sample, nil
}

// LossKeep is how long the samples of a tag are kept: the longest window.
const LossKeep = 24 * time.Hour

// lossKeepCount bounds the samples of a tag: a probe every minute for a day.
const lossKeepCount = 1440

type lossState struct {
	samples []LossSample
	// when a probe of the tag downloaded and could not count because its connections are not
	// its own: probing it again soon would not count either
	notCounted time.Time
	// when a probe of the tag was made last, and how many in a row failed (no count kept)
	lastAttempt time.Time
	failures    int
}

// StoreLossSample keeps a sample of a tag for LossKeep.
func (s *HistoryStorage) StoreLossSample(tag string, sample LossSample) {
	s.access.Lock()
	defer s.access.Unlock()
	state := s.detail.losses[tag]
	if state == nil {
		state = &lossState{}
		s.detail.losses[tag] = state
	}
	kept := state.samples[:0]
	for _, old := range state.samples {
		if sample.At.Sub(old.At) < LossKeep {
			kept = append(kept, old)
		}
	}
	if len(kept) >= lossKeepCount {
		kept = kept[len(kept)-lossKeepCount+1:]
	}
	state.samples = append(kept, sample)
	state.notCounted = time.Time{}
	state.lastAttempt = sample.At
	state.failures = 0
	s.notifyUpdated()
}

// StoreLossFailure records a probe of a tag that kept no count, and returns how many have
// failed in a row: the next one waits an interval, as after a count.
func (s *HistoryStorage) StoreLossFailure(tag string, at time.Time) int {
	s.access.Lock()
	defer s.access.Unlock()
	state := s.detail.losses[tag]
	if state == nil {
		state = &lossState{}
		s.detail.losses[tag] = state
	}
	state.lastAttempt = at
	state.failures++
	return state.failures
}

// LossAttempt returns when a probe of a tag was made last and how many in a row failed.
func (s *HistoryStorage) LossAttempt(tag string) (time.Time, int) {
	if s == nil {
		return time.Time{}, 0
	}
	s.access.RLock()
	defer s.access.RUnlock()
	if state := s.detail.losses[tag]; state != nil {
		return state.lastAttempt, state.failures
	}
	return time.Time{}, 0
}

// StoreLossNotCounted records that a probe of a tag could not count.
func (s *HistoryStorage) StoreLossNotCounted(tag string, at time.Time) {
	s.access.Lock()
	defer s.access.Unlock()
	state := s.detail.losses[tag]
	if state == nil {
		state = &lossState{}
		s.detail.losses[tag] = state
	}
	state.notCounted = at
	state.lastAttempt = at
}

// LossNotCounted returns when a probe of a tag last could not count, zero when the last
// probe counted or there was none.
func (s *HistoryStorage) LossNotCounted(tag string) time.Time {
	if s == nil {
		return time.Time{}
	}
	s.access.RLock()
	defer s.access.RUnlock()
	if state := s.detail.losses[tag]; state != nil {
		return state.notCounted
	}
	return time.Time{}
}

// LossWindow is the sum of the samples of a tag over the last hours.
type LossWindow struct {
	Hours    int
	Probes   int
	Segments int
	Lost     int
}

// Rate is the share of the segments that were lost, in percent.
func (w LossWindow) Rate() float64 {
	if w.Segments == 0 {
		return 0
	}
	return float64(w.Lost) * 100 / float64(w.Segments)
}

// LossWindowHours are the windows the loss of a server is told over.
var LossWindowHours = []int{1, 3, 6, 12, 24}

// LossWindows sums the samples of a tag over each of LossWindowHours before now.
func (s *HistoryStorage) LossWindows(tag string, now time.Time) []LossWindow {
	if s == nil {
		return nil
	}
	s.access.RLock()
	defer s.access.RUnlock()
	state := s.detail.losses[tag]
	if state == nil || len(state.samples) == 0 {
		return nil
	}
	windows := make([]LossWindow, len(LossWindowHours))
	for i, hours := range LossWindowHours {
		windows[i].Hours = hours
		for _, sample := range state.samples {
			if now.Sub(sample.At) < time.Duration(hours)*time.Hour {
				windows[i].Probes++
				windows[i].Segments += sample.Segments
				windows[i].Lost += sample.Lost
			}
		}
	}
	return windows
}

// LossOfWindow returns the shortest window of a tag with at least minSegments segments,
// false when even the longest has fewer: what the loss of the server is decided by, as
// recent as the probes allow.
func (s *HistoryStorage) LossOfWindow(tag string, now time.Time, minSegments int) (LossWindow, bool) {
	for _, window := range s.LossWindows(tag, now) {
		if window.Segments >= minSegments {
			return window, true
		}
	}
	return LossWindow{}, false
}

// LastLossSample returns the newest sample of a tag.
func (s *HistoryStorage) LastLossSample(tag string) (LossSample, bool) {
	if s == nil {
		return LossSample{}, false
	}
	s.access.RLock()
	defer s.access.RUnlock()
	state := s.detail.losses[tag]
	if state == nil || len(state.samples) == 0 {
		return LossSample{}, false
	}
	return state.samples[len(state.samples)-1], true
}

// LossRTT returns the least RTT the samples of a tag measured in the last LossKeep: the
// RTT of the path to the server, which the loss is weighed by.
func (s *HistoryStorage) LossRTT(tag string, now time.Time) time.Duration {
	if s == nil {
		return 0
	}
	s.access.RLock()
	defer s.access.RUnlock()
	state := s.detail.losses[tag]
	if state == nil {
		return 0
	}
	var least time.Duration
	for _, sample := range state.samples {
		if sample.RTT > 0 && now.Sub(sample.At) < LossKeep && (least == 0 || sample.RTT < least) {
			least = sample.RTT
		}
	}
	return least
}

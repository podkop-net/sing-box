package urltest

import (
	"slices"
	"time"
)

// historyDetail is what a HistoryStorage keeps of a tag beyond its last delay, under the lock of
// the storage: when its last URL test failed, while it has passed none since, and what its last
// download test found (for a block detector); the delays the URL tests of the last rounds
// measured (its delay is their median, over keeps[tag] rounds); whether its last URL test with a
// URL answered, per URL (a server may not reach one operator for good, as its hoster blocks it,
// and a URL that answered through it last time is the one to try once more after the URL of a
// round did not); its loss probes.
type historyDetail struct {
	failures  map[string]time.Time
	downloads map[string]DownloadResult
	samples   map[string][]Sample
	keeps     map[string]int
	links     map[string]map[string]bool
	losses    map[string]*lossState
}

func newHistoryDetail() historyDetail {
	return historyDetail{
		failures:  make(map[string]time.Time),
		downloads: make(map[string]DownloadResult),
		samples:   make(map[string][]Sample),
		keeps:     make(map[string]int),
		links:     make(map[string]map[string]bool),
		losses:    make(map[string]*lossState),
	}
}

// forget drops all that was found of a tag (DeleteURLTestHistory): it may be another outbound's
// by now. A failed test is StoreURLTestFailure.
func (d *historyDetail) forget(tag string) {
	delete(d.failures, tag)
	delete(d.downloads, tag)
	delete(d.samples, tag)
	delete(d.keeps, tag)
	delete(d.links, tag)
	delete(d.losses, tag)
}

// passed notes a URL test of a tag that passed (StoreURLTestHistory).
func (d *historyDetail) passed(tag string) {
	delete(d.failures, tag)
}

// Sample is the delay a URL test measured in a round (podkop-engine).
type Sample struct {
	Round int64
	Delay uint16
}

// DownloadResult is what a download test that could run found (podkop-engine).
type DownloadResult struct {
	At       time.Time
	Received int64
	// the body stopped on the way, after Received bytes
	Stopped bool
}

// StoreURLTestLinkResult keeps whether a URL test of a tag with link answered (podkop-engine).
// A failure of the tag as a whole (StoreURLTestFailure) leaves these alone: which URLs answer
// through a server is still known when it comes back.
func (s *HistoryStorage) StoreURLTestLinkResult(tag string, link string, answered bool) {
	s.access.Lock()
	defer s.access.Unlock()
	results := s.detail.links[tag]
	if results == nil {
		results = make(map[string]bool)
		s.detail.links[tag] = results
	}
	results[link] = answered
}

// URLTestLinkAnswered tells whether the last URL test of a tag with link answered, and whether
// one is known at all (podkop-engine).
func (s *HistoryStorage) URLTestLinkAnswered(tag string, link string) (answered bool, known bool) {
	if s == nil {
		return false, false
	}
	s.access.RLock()
	defer s.access.RUnlock()
	answered, known = s.detail.links[tag][link]
	return
}

// StoreURLTestFailure takes the result of a tag whose URL test failed away, as
// DeleteURLTestHistory does, and keeps the time of the failure (podkop-engine).
func (s *HistoryStorage) StoreURLTestFailure(tag string, at time.Time) {
	s.access.Lock()
	delete(s.delayHistory, tag)
	// what it measured before it went down says nothing of it when it comes back
	delete(s.detail.samples, tag)
	delete(s.detail.keeps, tag)
	s.detail.failures[tag] = at
	s.notifyUpdated()
	s.access.Unlock()
}

// StoreURLTestSample keeps the delay a URL test of a tag measured in a round and returns the
// median of the delays of the last keep rounds, this one among them (podkop-engine). The rounds
// of a group test its members with its URLs in turn, one a round: the median over as many
// rounds as there are URLs is the delay to every operator of them, which the delay to one of
// them is not (a server's way to one operator may be hundreds of milliseconds longer than to
// another), and one stray test does not move it. A round whose URL did not answer through
// the member has no sample: it is left out, not counted as slow. A later sample of the same
// round replaces the earlier one. The median of an even number is the mean of the two
// middle ones.
func (s *HistoryStorage) StoreURLTestSample(tag string, round int64, keep int, delay uint16) uint16 {
	if keep < 1 {
		keep = 1
	}
	s.access.Lock()
	defer s.access.Unlock()
	kept := make([]Sample, 0, keep)
	for _, sample := range s.detail.samples[tag] {
		// a round ahead of this one is of another schedule (a group that was replaced)
		if sample.Round > round-int64(keep) && sample.Round < round {
			kept = append(kept, sample)
		}
	}
	kept = append(kept, Sample{Round: round, Delay: delay})
	s.detail.samples[tag] = kept
	s.detail.keeps[tag] = keep
	return median(kept)
}

// URLTestSmoothed tells whether the delay of a tag is the median of several rounds
// (StoreURLTestSample): one test outside the rounds must not replace it (podkop-engine).
func (s *HistoryStorage) URLTestSmoothed(tag string) bool {
	if s == nil {
		return false
	}
	s.access.RLock()
	defer s.access.RUnlock()
	return s.detail.keeps[tag] > 1 && len(s.detail.samples[tag]) > 0
}

// LoadURLTestSamples returns the delays StoreURLTestSample keeps of a tag (podkop-engine).
func (s *HistoryStorage) LoadURLTestSamples(tag string) []Sample {
	if s == nil {
		return nil
	}
	s.access.RLock()
	defer s.access.RUnlock()
	return slices.Clone(s.detail.samples[tag])
}

func median(samples []Sample) uint16 {
	delays := make([]int, len(samples))
	for i, sample := range samples {
		delays[i] = int(sample.Delay)
	}
	slices.Sort(delays)
	middle := len(delays) / 2
	if len(delays)%2 == 1 {
		return uint16(delays[middle])
	}
	return uint16((delays[middle-1] + delays[middle] + 1) / 2)
}

// LoadURLTestFailure returns when the last URL test of a tag failed, if it has passed none since
// (podkop-engine).
func (s *HistoryStorage) LoadURLTestFailure(tag string) (at time.Time, loaded bool) {
	if s == nil {
		return
	}
	s.access.RLock()
	defer s.access.RUnlock()
	at, loaded = s.detail.failures[tag]
	return
}

// StoreDownloadResult keeps what a download test of a tag found (podkop-engine).
func (s *HistoryStorage) StoreDownloadResult(tag string, result DownloadResult) {
	s.access.Lock()
	s.detail.downloads[tag] = result
	s.access.Unlock()
}

// LoadDownloadResult returns what the last download test of a tag that could run found
// (podkop-engine).
func (s *HistoryStorage) LoadDownloadResult(tag string) (result DownloadResult, loaded bool) {
	if s == nil {
		return
	}
	s.access.RLock()
	defer s.access.RUnlock()
	result, loaded = s.detail.downloads[tag]
	return
}

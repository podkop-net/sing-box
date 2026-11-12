//go:build with_utls

package tls

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

const outcomeLocal = "192.0.2.10"

// outcomeClient makes a client with the fallback on over the cache; called again, it is the
// client after a restart.
func outcomeClient(t *testing.T, cache *choiceCache) (Config, context.Context) {
	t.Helper()
	setFallback(t, true)
	quietLog(t)
	ctx := service.ContextWith[adapter.CacheFile](context.Background(), adapter.CacheFile(cache))
	config, _ := fallbackClientIn(t, ctx, "chrome", true)
	return config, ctx
}

// settled waits for the writer of a client to have written all it was given.
func settled(t *testing.T, writer *detectOutcomeWriter) {
	t.Helper()
	require.Eventually(t, func() bool {
		writer.access.Lock()
		defer writer.access.Unlock()
		return !writer.writing && !writer.dirty
	}, 2*time.Second, time.Millisecond)
}

func writerOf(config Config) *detectOutcomeWriter {
	return &config.(*RealityClientConfig).uClient.fallback.outcome
}

// outcomeOf waits for the writes of the client and returns the only outcome in the cache.
func outcomeOf(t *testing.T, cache *choiceCache, writer *detectOutcomeWriter) outcomeEntry {
	t.Helper()
	settled(t, writer)
	cache.access.Lock()
	defer cache.access.Unlock()
	require.Len(t, cache.outcomes, 1)
	for _, entry := range cache.outcomes {
		return entry
	}
	return outcomeEntry{}
}

func (c *choiceCache) outcomeWriteCount() int {
	c.access.Lock()
	defer c.access.Unlock()
	return c.outcomeWrites
}

// answerOnce makes one dial whose first attempt completes the handshake.
func answerOnce(t *testing.T, ctx context.Context, config Config) string {
	t.Helper()
	dial := newDialOf(config)
	defer dial.done()
	require.NoError(t, dial.ready(ctx, fallbackServer))
	name := attemptName(t, dial, outcomeLocal)
	dial.answered()
	return name
}

// goThroughList makes dials whose ClientHellos all go unanswered until the list ends.
func goThroughList(t *testing.T, ctx context.Context, config Config) {
	t.Helper()
	for range 16 {
		dial := newDialOf(config)
		require.NoError(t, dial.ready(ctx, fallbackServer))
		for {
			attemptName(t, dial, outcomeLocal)
			again, err := dial.unanswered(fallbackServer)
			if again {
				continue
			}
			dial.done()
			if err != nil && strings.Contains(err.Error(), "unanswered with all of") {
				return
			}
			break
		}
	}
	t.Fatal("the list did not end")
}

// failList makes one dial of which the first candidate meets first and the others other.
func failList(t *testing.T, ctx context.Context, config Config, first error, other error) {
	t.Helper()
	dial := newDialOf(config)
	defer dial.done()
	require.NoError(t, dial.ready(ctx, fallbackServer))
	require.True(t, dial.failed(ctx, fallbackServer, attemptAndFail(t, dial, first)))
	require.True(t, dial.failed(ctx, fallbackServer, attemptAndFail(t, dial, other)))
	require.False(t, dial.failed(ctx, fallbackServer, attemptAndFail(t, dial, other)))
}

// firstRefused is what the first candidate meets at a server that takes it for a stranger's.
func firstRefused() error {
	return &realityStrangerError{E.New(realityVerificationFailed)}
}

// No ClientHello answered: no answer, and nothing else; a list that ends so does not say the
// server refused anything.
func TestDetectOutcomeNoAnswer(t *testing.T) {
	cache := &choiceCache{choices: make(map[string]choiceEntry)}
	config, ctx := outcomeClient(t, cache)
	goThroughList(t, ctx, config)
	entry := outcomeOf(t, cache, writerOf(config))
	require.Equal(t, adapter.DetectNoAnswer, entry.flags)
	require.Empty(t, entry.fingerprint)
}

// A wrong key: the first candidate is refused as a stranger's and the others fail. That is a
// failure of the handshake, and the refusal alone says nothing of the server.
func TestDetectOutcomeWrongKey(t *testing.T) {
	cache := &choiceCache{choices: make(map[string]choiceEntry)}
	config, ctx := outcomeClient(t, cache)
	failList(t, ctx, config, firstRefused(), E.New(realityVerificationFailed))
	entry := outcomeOf(t, cache, writerOf(config))
	require.Equal(t, adapter.DetectFailed, entry.flags)
	require.Empty(t, entry.fingerprint)
	require.False(t, config.(*RealityClientConfig).uClient.fallback.sawRefused, "what the list told is over with it")
}

// Refused takes a refusal of the first candidate and a later one that completes; it stays until
// the first one completes, and it is kept through a failure.
func TestDetectOutcomeRefused(t *testing.T) {
	cache := &choiceCache{choices: make(map[string]choiceEntry)}
	config, ctx := outcomeClient(t, cache)
	writer := writerOf(config)
	dial := newDialOf(config)
	require.NoError(t, dial.ready(ctx, fallbackServer))
	require.True(t, dial.failed(ctx, fallbackServer, attemptAndFail(t, dial, firstRefused())))
	settled(t, writer)
	require.Zero(t, cache.outcomeWriteCount(), "refused before anything completed")
	require.Equal(t, "firefox", attemptName(t, dial, outcomeLocal))
	dial.answered()
	dial.done()
	entry := outcomeOf(t, cache, writer)
	require.Equal(t, adapter.DetectRefused, entry.flags)
	require.Equal(t, "firefox", entry.fingerprint)
	cache.wait(t, "firefox")

	// kept after a restart, and through a failure of the whole list
	config, ctx = outcomeClient(t, cache)
	writer = writerOf(config)
	require.Equal(t, "firefox", answerOnce(t, ctx, config))
	require.Equal(t, adapter.DetectRefused, outcomeOf(t, cache, writer).flags)
	rest := utlsFallbackRest
	utlsFallbackRest = time.Millisecond
	t.Cleanup(func() { utlsFallbackRest = rest })
	goThroughList(t, ctx, config)
	require.Equal(t, adapter.DetectRefused|adapter.DetectNoAnswer, outcomeOf(t, cache, writer).flags)
	time.Sleep(5 * time.Millisecond)
	require.Equal(t, "firefox", answerOnce(t, ctx, config))
	entry = outcomeOf(t, cache, writer)
	require.Equal(t, adapter.DetectRefused, entry.flags)
	require.Equal(t, "firefox", entry.fingerprint)

	// the choice got old: the first candidate is tried again, and it completes
	fallback := config.(*RealityClientConfig).uClient.fallback
	fallback.access.Lock()
	fallback.paths[0].chosen = time.Now().Add(-2 * utlsFallbackRecheck)
	fallback.access.Unlock()
	require.Equal(t, chromeWithout, answerOnce(t, ctx, config))
	entry = outcomeOf(t, cache, writer)
	require.Zero(t, entry.flags)
	require.Equal(t, chromeWithout, entry.fingerprint)
}

// A saved choice has worked here, so a failure of another kind does not walk the list. A failed
// verification of it is still a failure of the handshake: the key of the link has changed, and the
// record says so. The dial goes as it did, and a handshake that completes clears it.
func TestDetectOutcomeFailedOnSavedChoice(t *testing.T) {
	cache := &choiceCache{choices: make(map[string]choiceEntry)}
	config, ctx := outcomeClient(t, cache)
	dial := newDialOf(config)
	require.NoError(t, dial.ready(ctx, fallbackServer))
	require.True(t, dial.failed(ctx, fallbackServer, attemptAndFail(t, dial, firstRefused())))
	require.Equal(t, "firefox", attemptName(t, dial, outcomeLocal))
	dial.answered()
	dial.done()
	cache.wait(t, "firefox")
	require.Equal(t, adapter.DetectRefused, outcomeOf(t, cache, writerOf(config)).flags)

	config, ctx = outcomeClient(t, cache)
	writer := writerOf(config)
	failSaved := func(ctx context.Context, err error) {
		t.Helper()
		dial := newDialOf(config)
		defer dial.done()
		require.NoError(t, dial.ready(context.Background(), fallbackServer))
		require.False(t, dial.failed(ctx, fallbackServer, attemptAndFail(t, dial, err)), "the dial ends as it did")
	}

	// another failure says nothing of the key, and a dial its caller gave up nothing at all
	failSaved(ctx, io.ErrUnexpectedEOF)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	failSaved(canceled, E.New(realityVerificationFailed))
	settled(t, writer)
	require.Equal(t, adapter.DetectRefused, outcomeOf(t, cache, writer).flags)

	failSaved(ctx, E.New(realityVerificationFailed))
	entry := outcomeOf(t, cache, writer)
	require.Equal(t, adapter.DetectRefused|adapter.DetectFailed, entry.flags)
	require.Empty(t, entry.fingerprint)
	// the same state again writes nothing
	writes := cache.outcomeWriteCount()
	failSaved(ctx, E.New(realityVerificationFailed))
	settled(t, writer)
	require.Equal(t, writes, cache.outcomeWriteCount())

	require.Equal(t, "firefox", answerOnce(t, ctx, config))
	require.Equal(t, adapter.DetectRefused, outcomeOf(t, cache, writer).flags)
}

// A path with a saved choice writes no choice when it recovers: its handshake clears the failure
// all the same, during the rest and after it.
func TestDetectOutcomeRecoveryWithSavedChoice(t *testing.T) {
	cache := &choiceCache{choices: make(map[string]choiceEntry)}
	config, ctx := outcomeClient(t, cache)
	dial := newDialOf(config)
	require.NoError(t, dial.ready(ctx, fallbackServer))
	attemptName(t, dial, outcomeLocal)
	lost(t, dial)
	attemptName(t, dial, outcomeLocal)
	lost(t, dial)
	require.Equal(t, "firefox", attemptName(t, dial, outcomeLocal))
	dial.answered()
	dial.done()
	cache.wait(t, "firefox")
	require.Equal(t, "firefox", outcomeOf(t, cache, writerOf(config)).fingerprint)

	for _, inRest := range []bool{true, false} {
		config, ctx = outcomeClient(t, cache)
		writer := writerOf(config)
		choiceWrites := cache.writeCount()
		goThroughList(t, ctx, config)
		entry := outcomeOf(t, cache, writer)
		require.Equal(t, adapter.DetectNoAnswer, entry.flags)
		if !inRest {
			fallback := config.(*RealityClientConfig).uClient.fallback
			fallback.access.Lock()
			fallback.paths[0].restUntil = time.Time{}
			fallback.access.Unlock()
		}
		require.Equal(t, "firefox", answerOnce(t, ctx, config))
		require.Equal(t, choiceWrites, cache.writeCount(), "the choice did not change")
		entry = outcomeOf(t, cache, writer)
		require.Zero(t, entry.flags)
		require.Equal(t, "firefox", entry.fingerprint)
	}
}

// A dial of a candidate the path has left clears the failure and gives no fingerprint, even when
// none is known: the next dial of the candidate in use does.
func TestDetectOutcomeLeftCandidate(t *testing.T) {
	cache := &choiceCache{choices: make(map[string]choiceEntry)}
	config, ctx := outcomeClient(t, cache)
	writer := writerOf(config)
	slow := newDialOf(config)
	require.NoError(t, slow.ready(ctx, fallbackServer))
	require.Equal(t, chromeWithout, attemptName(t, slow, outcomeLocal))
	dial := newDialOf(config)
	attemptName(t, dial, outcomeLocal)
	lost(t, dial)
	attemptName(t, dial, outcomeLocal)
	lost(t, dial)
	require.Equal(t, "firefox", attemptName(t, dial, outcomeLocal))
	dial.answered()
	require.Equal(t, "firefox", outcomeOf(t, cache, writer).fingerprint)
	writer.failed(time.Now(), adapter.DetectNoAnswer)
	slow.answered()
	slow.done()
	entry := outcomeOf(t, cache, writer)
	require.Zero(t, entry.flags)
	require.Empty(t, entry.fingerprint)
	require.Equal(t, "firefox", answerOnce(t, ctx, config))
	entry = outcomeOf(t, cache, writer)
	require.Zero(t, entry.flags)
	require.Equal(t, "firefox", entry.fingerprint)
}

// Written only on a change: not by more handshakes, a restart or another list that ends the same;
// two paths with candidates of their own do not write by turns.
func TestDetectOutcomeWritesOnChange(t *testing.T) {
	cache := &choiceCache{choices: make(map[string]choiceEntry)}
	config, ctx := outcomeClient(t, cache)
	writer := writerOf(config)
	for range 5 {
		require.Equal(t, chromeWithout, answerOnce(t, ctx, config))
	}
	settled(t, writer)
	require.Equal(t, 1, cache.outcomeWriteCount())
	require.Equal(t, chromeWithout, outcomeOf(t, cache, writer).fingerprint)
	cache.wait(t, chromeWithout)

	// a restart reads the state
	config, ctx = outcomeClient(t, cache)
	writer = writerOf(config)
	for range 5 {
		require.Equal(t, chromeWithout, answerOnce(t, ctx, config))
	}
	settled(t, writer)
	require.Equal(t, 1, cache.outcomeWriteCount())

	// the same failure twice is one write
	rest := utlsFallbackRest
	utlsFallbackRest = time.Millisecond
	t.Cleanup(func() { utlsFallbackRest = rest })
	goThroughList(t, ctx, config)
	settled(t, writer)
	require.Equal(t, 2, cache.outcomeWriteCount())
	time.Sleep(5 * time.Millisecond)
	goThroughList(t, ctx, config)
	settled(t, writer)
	require.Equal(t, 2, cache.outcomeWriteCount())
	require.Equal(t, adapter.DetectNoAnswer, outcomeOf(t, cache, writer).flags)

	// another path goes on to its own candidate: told once, then the paths do not write by turns
	time.Sleep(5 * time.Millisecond)
	require.Equal(t, chromeWithout, answerOnce(t, ctx, config))
	settled(t, writer)
	require.Equal(t, 3, cache.outcomeWriteCount())
	second := newDialOf(config)
	require.Equal(t, chromeWithout, attemptName(t, second, "198.51.100.7"))
	lost(t, second)
	attemptName(t, second, "198.51.100.7")
	lost(t, second)
	require.Equal(t, "firefox", attemptName(t, second, "198.51.100.7"))
	second.answered()
	second.done()
	settled(t, writer)
	require.Equal(t, 4, cache.outcomeWriteCount())
	for range 5 {
		dial := newDialOf(config)
		attemptName(t, dial, outcomeLocal)
		dial.answered()
		dial.done()
		dial = newDialOf(config)
		require.Equal(t, "firefox", attemptName(t, dial, "198.51.100.7"))
		dial.answered()
		dial.done()
	}
	settled(t, writer)
	require.Equal(t, 4, cache.outcomeWriteCount())
}

// The failure of an earlier run tells nothing of this one: the first failure of a process is
// written with its own time, once.
func TestDetectOutcomeFailureAfterRestart(t *testing.T) {
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	cache := &choiceCache{choices: make(map[string]choiceEntry)}
	key := "chrome example.org " + fallbackServer.String()
	require.NoError(t, cache.StoreDetectOutcome(key, adapter.DetectNoAnswer, "", old))
	config, ctx := outcomeClient(t, cache)
	writer := writerOf(config)
	rest := utlsFallbackRest
	utlsFallbackRest = time.Millisecond
	t.Cleanup(func() { utlsFallbackRest = rest })
	goThroughList(t, ctx, config)
	entry := outcomeOf(t, cache, writer)
	require.Equal(t, adapter.DetectNoAnswer, entry.flags)
	require.True(t, entry.at.After(old), "the failure kept the time of the earlier run")
	require.Equal(t, 2, cache.outcomeWriteCount())
	time.Sleep(5 * time.Millisecond)
	goThroughList(t, ctx, config)
	settled(t, writer)
	require.Equal(t, 2, cache.outcomeWriteCount())
}

// blockingCache holds the writes until told to go on, and watches how many run at once.
type blockingCache struct {
	choiceCache
	gate    chan struct{}
	running int
	most    int
	order   []byte
	guard   sync.Mutex
}

func (c *blockingCache) StoreDetectOutcome(key string, flags byte, fingerprint string, at time.Time) error {
	c.guard.Lock()
	c.running++
	c.most = max(c.most, c.running)
	c.order = append(c.order, flags)
	c.guard.Unlock()
	<-c.gate
	c.guard.Lock()
	c.running--
	c.guard.Unlock()
	return nil
}

// One goroutine at most, in order, and what came meanwhile is written as the latest state.
func TestDetectOutcomeWriterOrder(t *testing.T) {
	cache := &blockingCache{gate: make(chan struct{})}
	writer := new(detectOutcomeWriter)
	writer.open(cache, "key")
	now := time.Now()
	writer.failed(now, adapter.DetectNoAnswer)
	require.Eventually(t, func() bool {
		cache.guard.Lock()
		defer cache.guard.Unlock()
		return cache.running == 1
	}, 2*time.Second, time.Millisecond)
	writer.failed(now, adapter.DetectFailed)
	writer.failed(now, adapter.DetectNoAnswer)
	writer.answered(now, func(byte, string) (byte, string) { return 0, "firefox" })
	close(cache.gate)
	settled(t, writer)
	require.Equal(t, 1, cache.most)
	require.Equal(t, []byte{adapter.DetectNoAnswer, 0}, cache.order)
}

// The fallback off: a success clears all, no answer takes two deadlines in a row, a failed
// verification is a failure at once, and nothing is written when nothing changes.
func TestDetectOutcomeFallbackOff(t *testing.T) {
	setFallback(t, false)
	cache := &choiceCache{choices: make(map[string]choiceEntry)}
	ctx := service.ContextWith[adapter.CacheFile](context.Background(), adapter.CacheFile(cache))
	config, _ := fallbackClientIn(t, ctx, "chrome", true)
	reality := config.(*RealityClientConfig)
	require.Nil(t, reality.uClient.fallback)
	writer := reality.outcome
	// a clone records with the same writer
	recorder := config.Clone().(detectRecorder)
	require.Same(t, writer, config.Clone().(*RealityClientConfig).outcome)

	recorder.recordDetectOutcome(context.Background(), fallbackServer, nil)
	entry := outcomeOf(t, cache, writer)
	require.Zero(t, entry.flags)
	require.Equal(t, "chrome", entry.fingerprint)
	for range 5 {
		recorder.recordDetectOutcome(context.Background(), fallbackServer, nil)
	}
	settled(t, writer)
	require.Equal(t, 1, cache.outcomeWriteCount())
	cache.access.Lock()
	for key := range cache.outcomes {
		require.Equal(t, "chrome example.org "+fallbackServer.String(), key)
	}
	cache.access.Unlock()

	// one deadline, broken by a server that answered: nothing
	recorder.recordDetectOutcome(context.Background(), fallbackServer, context.DeadlineExceeded)
	recorder.recordDetectOutcome(context.Background(), fallbackServer, io.EOF)
	recorder.recordDetectOutcome(context.Background(), fallbackServer, E.Cause(context.DeadlineExceeded, "handshake"))
	settled(t, writer)
	require.Equal(t, 1, cache.outcomeWriteCount())
	// a caller that gave up neither counts nor breaks the row
	recorder.recordDetectOutcome(context.Background(), fallbackServer, context.Canceled)
	settled(t, writer)
	require.Equal(t, 1, cache.outcomeWriteCount())
	// nor does a deadline of the caller's that cut it, whether its context knows it yet or not
	// (the round of a group test that ran out)
	ended, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	for _, caller := range []context.Context{ended, deadlinePassed{}} {
		recorder.recordDetectOutcome(caller, fallbackServer, E.Cause(context.DeadlineExceeded, "handshake"))
		recorder.recordDetectOutcome(caller, fallbackServer, os.ErrDeadlineExceeded)
	}
	settled(t, writer)
	require.Equal(t, 1, cache.outcomeWriteCount())
	// the second in a row
	recorder.recordDetectOutcome(context.Background(), fallbackServer, E.Cause(context.DeadlineExceeded, "handshake"))
	entry = outcomeOf(t, cache, writer)
	require.Equal(t, adapter.DetectNoAnswer, entry.flags)
	require.Empty(t, entry.fingerprint)

	recorder.recordDetectOutcome(context.Background(), fallbackServer, nil)
	entry = outcomeOf(t, cache, writer)
	require.Zero(t, entry.flags)
	require.Equal(t, "chrome", entry.fingerprint)

	// a failed verification, in each form it comes in
	for _, failure := range []error{
		E.New(realityVerificationFailed),
		firstRefused(),
		E.Cause(errors.New("x"), realityVerificationFailed),
	} {
		recorder.recordDetectOutcome(context.Background(), fallbackServer, failure)
		entry = outcomeOf(t, cache, writer)
		require.Equal(t, adapter.DetectFailed, entry.flags)
		recorder.recordDetectOutcome(context.Background(), fallbackServer, nil)
		require.Zero(t, outcomeOf(t, cache, writer).flags)
	}
}

// deadlinePassed is the context of a dial whose deadline has come while its timer has not closed
// it yet.
type deadlinePassed struct{}

func (deadlinePassed) Deadline() (time.Time, bool) { return time.Now().Add(-time.Millisecond), true }
func (deadlinePassed) Done() <-chan struct{}       { return nil }
func (deadlinePassed) Err() error                  { return nil }
func (deadlinePassed) Value(any) any               { return nil }

// Without a cache file in the context (a probe of the backend) nothing is recorded.
func TestDetectOutcomeWithoutCache(t *testing.T) {
	setFallback(t, false)
	config, _ := fallbackClientIn(t, context.Background(), "chrome", true)
	reality := config.(*RealityClientConfig)
	reality.recordDetectOutcome(context.Background(), M.ParseSocksaddrHostPort("192.0.2.1", 443), nil)
	require.Nil(t, reality.outcome.cache)
}

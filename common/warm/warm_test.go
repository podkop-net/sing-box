package warm

import (
	"sync"
	"testing"
	"time"
)

// Functions one after another run on one worker; a worker waits idle, then ends.
func TestPoolReusesItsWorker(t *testing.T) {
	pool := New(4, 200*time.Millisecond)
	for range 10 {
		done := make(chan struct{})
		pool.Go(func() { close(done) })
		<-done
		time.Sleep(time.Millisecond)
	}
	if got := pool.Started(); got != 1 {
		t.Fatalf("started %d workers for functions one after another, want 1", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for pool.Workers() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if pool.Workers() != 0 {
		t.Fatalf("%d workers left after their wait", pool.Workers())
	}
}

// A caller never waits: past most busy workers, a function gets a goroutine of its own.
func TestPoolNeverWaits(t *testing.T) {
	pool := New(2, time.Second)
	release := make(chan struct{})
	var running sync.WaitGroup
	running.Add(5)
	for range 5 {
		pool.Go(func() {
			running.Done()
			<-release
		})
	}
	waited := make(chan struct{})
	go func() { running.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		t.Fatal("not every function started while the workers were busy")
	}
	if got := pool.Workers(); got != 2 {
		t.Fatalf("%d workers, want the most, 2", got)
	}
	close(release)
}

// deep uses a few KB of stack a call, as the route of a session does.
//
//go:noinline
func deep(depth int) byte {
	var frame [512]byte
	frame[depth%len(frame)] = byte(depth)
	if depth == 0 {
		return frame[0]
	}
	return deep(depth-1) + frame[depth%len(frame)]
}

// A deep function on a new goroutine against on a warm worker: the stack copied larger each time,
// or once.
func BenchmarkDeepOnNewGoroutine(b *testing.B) {
	for range b.N {
		done := make(chan struct{})
		go func() { deep(64); close(done) }()
		<-done
	}
}

func BenchmarkDeepOnWarmWorker(b *testing.B) {
	pool := New(4, time.Minute)
	for range b.N {
		done := make(chan struct{})
		pool.Go(func() { deep(64); close(done) })
		<-done
	}
}

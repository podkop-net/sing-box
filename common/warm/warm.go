// Package warm runs functions on goroutines that are kept for a while after they finish one.
//
// A new goroutine starts with a small stack, and the runtime keeps no grown stack for the next
// goroutine when one exits: a path deeper than that stack (the route of a new UDP session, a DNS
// exchange) copies its stack larger, often more than once, every time it runs on a new
// goroutine. A worker of the pool keeps the stack it grew while it waits for the next function;
// the garbage collector may still shrink the stack of a worker that waits, so the growth comes
// back at most once a collection, not once a function.
package warm

import (
	"sync/atomic"
	"time"
)

// Pool hands functions to its waiting workers. It never makes a caller wait: with no worker
// waiting, a function gets a new goroutine, which joins the pool while the pool has room.
type Pool struct {
	jobs chan func()
	idle time.Duration
	most int32
	// workers are the goroutines of the pool, busy or waiting; started counts every one made
	workers atomic.Int32
	started atomic.Int64
}

// New makes a pool of at most most workers, each of which ends after waiting idle.
func New(most int, idle time.Duration) *Pool {
	return &Pool{jobs: make(chan func()), idle: idle, most: int32(most)}
}

// Go runs f on a waiting worker, or on a new goroutine.
func (p *Pool) Go(f func()) {
	select {
	case p.jobs <- f:
		return
	default:
	}
	if p.workers.Add(1) <= p.most {
		p.started.Add(1)
		go p.work(f)
		return
	}
	p.workers.Add(-1)
	go f()
}

func (p *Pool) work(f func()) {
	defer p.workers.Add(-1)
	timer := time.NewTimer(p.idle)
	defer timer.Stop()
	for {
		f()
		f = nil
		timer.Reset(p.idle)
		select {
		case f = <-p.jobs:
		case <-timer.C:
			return
		}
	}
}

// Workers is how many workers the pool has now, busy or waiting; Started how many it made.
func (p *Pool) Workers() int { return int(p.workers.Load()) }

func (p *Pool) Started() int64 { return p.started.Load() }

// The pool of the process. At DNS saturation (16 queries at a time, one core of an arm64 server)
// at most 8 workers were busy or waiting, and the process held no more memory than without the
// pool; 64 bounds what a burst may keep. A worker waits 10 s, as a DNS session waits for its next
// packet (C.DNSTimeout): every worker had ended 15 s after the load.
var (
	defaultWorkers = 64
	defaultIdle    = 10 * time.Second
	defaultPool    = New(defaultWorkers, defaultIdle)
)

// Go runs f on a worker of the pool of the process (Pool.Go).
func Go(f func()) {
	defaultPool.Go(f)
}

// Default is the pool of the process.
func Default() *Pool {
	return defaultPool
}

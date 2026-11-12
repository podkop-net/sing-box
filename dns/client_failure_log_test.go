package dns

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"

	mDNS "github.com/miekg/dns"
)

type lockedBuffer struct {
	access sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.access.Lock()
	defer b.access.Unlock()
	return b.buffer.Write(p)
}

func (b *lockedBuffer) lines() []string {
	b.access.Lock()
	defer b.access.Unlock()
	return strings.Split(strings.TrimSpace(b.buffer.String()), "\n")
}

// A real logger: it panics on argument types it does not format.
func TestFailureLog(t *testing.T) {
	failureLogInterval = 100 * time.Millisecond
	defer func() { failureLogInterval = 10 * time.Second }()
	output := new(lockedBuffer)
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now(), DisableColors: true}, output, "", nil, false)
	if err := factory.Start(); err != nil {
		t.Fatal(err)
	}
	logger := factory.NewLogger("dns")
	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	var failures failureLog

	if err := failures.failed(context.Background(), logger, "doh", message, context.Canceled); IsLoggedFailure(err) {
		t.Fatal("a query given up by its caller was logged")
	}
	timeout := E.Cause(context.DeadlineExceeded, "dial")
	err := failures.failed(context.Background(), logger, "doh", message, timeout)
	if !IsLoggedFailure(err) || !E.IsCanceled(err) {
		t.Fatal("the logged failure lost its cause: ", err)
	}
	if failures.failed(context.Background(), logger, "doh", message, err) != err {
		t.Fatal("a logged failure was taken again")
	}
	for i := 0; i < 5; i++ {
		failures.failed(context.Background(), logger, "doh", message, timeout)
	}
	failures.failed(context.Background(), logger, "dot", message, timeout)
	// the windows close one interval after their last summary: wait for it, timers can
	// run late on a loaded machine
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		failures.access.Lock()
		open := len(failures.windows)
		failures.access.Unlock()
		if open == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("windows stay open after the failures stopped: ", open)
		}
	}

	lines := output.lines()
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d: %q", len(lines), lines)
	}
	if !strings.Contains(lines[0], "server doh: exchange failed for example.com. IN A: dial: context deadline exceeded") ||
		!strings.Contains(lines[1], "server dot: exchange failed for") ||
		!strings.Contains(lines[2], "server doh: 5 more exchanges failed in 100ms, the last for example.com. IN A") {
		t.Fatalf("unexpected lines: %q", lines)
	}
}

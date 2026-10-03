package v2rayhttp

import (
	"io"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// When RoundTrip fails (the server cannot be dialled), the request never establishes and
// nothing reads the request-body pipe. A Write that started before the failure must not
// block for ever: the client closes the read end of the pipe with the error, so the write
// returns that error. Without the fix this test hangs and the goroutine and socket of every
// such attempt leak, as they did in the gRPC-lite transport.
func TestLateHTTPConnWriteUnblocksOnSetupError(t *testing.T) {
	t.Parallel()
	pipeReader, pipeWriter := io.Pipe()
	defer pipeReader.Close()
	conn := NewLateHTTPConn(pipeWriter)

	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("handshake"))
		writeErr <- err
	}()

	// the write is now blocked on the pipe that nobody reads
	select {
	case <-writeErr:
		t.Fatal("write returned before the request failed")
	case <-time.After(100 * time.Millisecond):
	}

	pipeReader.CloseWithError(syscall.ECONNREFUSED)
	conn.Setup(nil, syscall.ECONNREFUSED)

	// the blocked write returns the dial error itself instead of hanging (the field case: the
	// server refuses or is blackholed)
	select {
	case err := <-writeErr:
		require.ErrorIs(t, err, syscall.ECONNREFUSED)
	case <-time.After(5 * time.Second):
		t.Fatal("write still blocked after setup failed: the goroutine and socket would leak")
	}

	// a write after the failure also returns at once, it does not block
	done := make(chan struct{})
	go func() {
		conn.Write([]byte("after"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a write after the failure blocked")
	}
}

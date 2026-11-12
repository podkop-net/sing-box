package readwait

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	sbufio "github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// fakeStream is a stream with a quic-go style Peek over a pipe. A Read that has to wait
// for data counts as a failure: the read waiter must call Read only once data is there.
type fakeStream struct {
	net.Conn
	reader      *bufio.Reader
	earlyReads  atomic.Int32
	peeks       atomic.Int32
	readLengths []int
}

func newFakeStream(conn net.Conn) *fakeStream {
	return &fakeStream{Conn: conn, reader: bufio.NewReader(conn)}
}

func (s *fakeStream) Peek(b []byte) (int, error) {
	s.peeks.Add(1)
	peeked, err := s.reader.Peek(len(b))
	return copy(b, peeked), err
}

func (s *fakeStream) Read(b []byte) (int, error) {
	buffered := s.reader.Buffered()
	s.readLengths = append(s.readLengths, len(b))
	n, err := s.reader.Read(b)
	if buffered == 0 && n > 0 {
		s.earlyReads.Add(1) // the read had to wait for this data
	}
	return n, err
}

// The copy loop of sing finds the read waiter, waits with Peek and reads only once data has
// arrived, with the full buffer; the bytes arrive intact and in order.
func TestQUICStreamConnCopy(t *testing.T) {
	remote, local := net.Pipe()
	stream := newFakeStream(local)
	conn := NewQUICStreamConn(stream)
	_, isCreator := conn.(N.ReadWaitCreator)
	require.True(t, isCreator)

	var output bytes.Buffer
	done := make(chan error, 1)
	go func() {
		_, err := sbufio.Copy(&output, conn)
		done <- err
	}()
	var sent bytes.Buffer
	for i := 0; i < 5; i++ {
		chunk := bytes.Repeat([]byte{byte('a' + i)}, 100*(i+1))
		sent.Write(chunk)
		_, err := remote.Write(chunk)
		require.NoError(t, err)
		time.Sleep(20 * time.Millisecond) // the copy loop waits in between
	}
	remote.Close()
	require.NoError(t, <-done)
	require.Equal(t, sent.Bytes(), output.Bytes())
	require.Zero(t, stream.earlyReads.Load(), "a read waited for data while holding the buffer")
	require.Greater(t, stream.peeks.Load(), int32(0))
	for _, length := range stream.readLengths {
		require.GreaterOrEqual(t, length, 4096, "the read did not get the copy loop's buffer")
	}
}

// A connection without Peek is returned as it is.
func TestQUICStreamConnWithoutPeek(t *testing.T) {
	side, peer := net.Pipe()
	defer side.Close()
	defer peer.Close()
	require.Equal(t, side, NewQUICStreamConn(side))
}

type scriptedReader struct {
	results []readResult
}

type readResult struct {
	data string
	err  error
}

func (r *scriptedReader) Read(b []byte) (int, error) {
	if len(r.results) == 0 {
		return 0, io.EOF
	}
	result := r.results[0]
	r.results = r.results[1:]
	return copy(b, result.data), result.err
}

// Data that comes with an error is delivered first, the error with the next call; empty
// reads (empty frames) are skipped; a failed wait with an empty read ends the waiting.
func TestPeekWaiterResults(t *testing.T) {
	failure := errors.New("reset")
	reader := &scriptedReader{results: []readResult{{"", nil}, {"data", failure}}}
	waiter := NewPeekWaiter(reader, func() error { return nil })
	waiter.InitializeReadWaiter(N.ReadWaitOptions{})
	buffer, err := waiter.WaitReadBuffer()
	require.NoError(t, err)
	require.Equal(t, "data", string(buffer.Bytes()))
	buffer.Release()
	_, err = waiter.WaitReadBuffer()
	require.ErrorIs(t, err, failure)

	waitFailure := errors.New("deadline")
	reader = &scriptedReader{results: []readResult{{"", nil}}}
	waiter = NewPeekWaiter(reader, func() error { return waitFailure })
	waiter.InitializeReadWaiter(N.ReadWaitOptions{})
	_, err = waiter.WaitReadBuffer()
	require.ErrorIs(t, err, waitFailure)
}

// The same stream without the read waiter: sing's copy loop reads with its buffer before the
// data is there, which is what the read waiter avoids (and what the check above detects).
func TestCopyWithoutReadWaiterHoldsBuffer(t *testing.T) {
	remote, local := net.Pipe()
	stream := newFakeStream(local)
	done := make(chan error, 1)
	go func() {
		_, err := sbufio.Copy(io.Discard, stream)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	_, err := remote.Write([]byte("data"))
	require.NoError(t, err)
	remote.Close()
	require.NoError(t, <-done)
	require.Positive(t, stream.earlyReads.Load())
}

package v2rayxhttp

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/stretchr/testify/require"
)

// writeAfterEnd writes until a write fails, after the server ended the request that
// carries the upload: the HTTP client then closes the body of that request.
func writeAfterEnd(t *testing.T, client *Client) error {
	t.Helper()
	conn, err := client.DialContext(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	_, err = conn.Write([]byte("first"))
	require.NoError(t, err)
	_, err = io.ReadFull(conn, make([]byte, 5))
	require.NoError(t, err)
	var writeErr error
	require.Eventually(t, func() bool {
		_, writeErr = conn.Write([]byte("late"))
		return writeErr != nil
	}, 5*time.Second, 10*time.Millisecond)
	return writeErr
}

// The server ending its answer to the stream-up upload, as Xray does once the
// connection is over, makes a later write (a TLS close_notify sent on the FIN of
// the destination, say) fail as closed: sing-box takes that for the end of the
// connection, not for an error to log.
func TestXHTTPStreamUpWriteAfterUploadEnded(t *testing.T) {
	client, _ := newTestPair(t, option.V2RayXHTTPOptions{Mode: modeStreamUp}, "h2", func(s *testServer) { s.endUploadAfterData = true })
	err := writeAfterEnd(t, client)
	require.True(t, E.IsClosed(err), "write after the end of the upload: %T %v", err, err)
}

// The same for stream-one, where one request carries both halves.
func TestXHTTPStreamOneWriteAfterEnd(t *testing.T) {
	client, _ := newTestPair(t, option.V2RayXHTTPOptions{Mode: modeStreamOne}, "h2", func(s *testServer) { s.endStreamOneAfterData = true })
	err := writeAfterEnd(t, client)
	require.True(t, E.IsClosed(err), "write after the end of the stream-one request: %T %v", err, err)
}

// A reset of the stream-up upload after its answer began is a failure of the
// session: the download ends with its cause, not as a clean end, and does not
// wait on with nothing written.
func TestXHTTPStreamUpUploadResetFailsSession(t *testing.T) {
	client, _ := newTestPair(t, option.V2RayXHTTPOptions{Mode: modeStreamUp}, "h2", func(s *testServer) { s.resetUploadAfterData = true })
	conn, err := client.DialContext(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("first"))
	require.NoError(t, err)
	// the echo may come before the reset ends the session, or not
	readErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, 64)
		for {
			if _, err := conn.Read(buffer); err != nil {
				readErr <- err
				return
			}
		}
	}()
	select {
	case err = <-readErr:
	case <-time.After(5 * time.Second):
		t.Fatal("the download still waits after the upload was reset")
	}
	require.False(t, E.IsClosed(err), "a reset upload reads as a clean end: %v", err)
	_, err = conn.Write([]byte("late"))
	require.Error(t, err)
	require.False(t, E.IsClosed(err), "write after a reset upload: %v", err)
}

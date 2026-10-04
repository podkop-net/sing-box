package clashapi

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"github.com/stretchr/testify/require"
)

func newListenTestServer(t *testing.T, address string) *Server {
	saved := listenRetryDelay
	listenRetryDelay = 20 * time.Millisecond
	t.Cleanup(func() { listenRetryDelay = saved })
	return &Server{
		logger: log.NewNOPFactory().NewLogger("clash-api"),
		httpServer: &http.Server{Addr: address, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})},
		closed:             make(chan struct{}),
		externalController: true,
	}
}

func answers(address string) bool {
	client := &http.Client{Timeout: 200 * time.Millisecond}
	response, err := client.Get("http://" + address + "/")
	if err != nil {
		return false
	}
	response.Body.Close()
	return response.StatusCode == http.StatusNoContent
}

// An address taken by another program does not fail the start: the API comes up once the
// address is free.
func TestExternalControllerListenRetried(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := blocker.Addr().String()
	server := newListenTestServer(t, address)
	require.NoError(t, server.Start(adapter.StartStateStarted))
	defer server.Close()

	blocker.Close()
	require.Eventually(t, func() bool { return answers(address) }, 5*time.Second, 20*time.Millisecond)
}

// A server closed while it waits to retry does not listen afterwards.
func TestExternalControllerRetryEndsOnClose(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := blocker.Addr().String()
	server := newListenTestServer(t, address)
	require.NoError(t, server.Start(adapter.StartStateStarted))
	require.NoError(t, server.Close())

	blocker.Close()
	time.Sleep(200 * time.Millisecond)
	_, err = net.DialTimeout("tcp", address, 200*time.Millisecond)
	require.Error(t, err)
}

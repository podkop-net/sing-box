package mixed_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type quietWriter struct{}

func (quietWriter) WriteMessage(log.Level, string) {}

func startProxy(t *testing.T) (*box.Box, string) {
	t.Chdir(t.TempDir())
	free, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := free.Addr().(*net.TCPAddr)
	free.Close()
	ctx := include.Context(service.ContextWith[deprecated.Manager](context.Background(), deprecated.NewStderrManager(log.StdLogger())))
	var options option.Options
	require.NoError(t, options.UnmarshalJSONContext(ctx, []byte(fmt.Sprint(`{
		"inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": `, address.Port, `, "users": [{"username": "user", "password": "old"}]}],
		"outbounds": [{"type": "direct", "tag": "direct"}]
	}`))))
	instance, err := box.New(box.Options{Context: ctx, Options: options, PlatformLogWriter: quietWriter{}})
	require.NoError(t, err)
	require.NoError(t, instance.Start())
	t.Cleanup(func() { instance.Close() })
	return instance, address.String()
}

func proxyRequest(conn net.Conn, reader *bufio.Reader, method, target string) (*http.Response, error) {
	_, err := fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic %s\r\n\r\n",
		method, target, strings.TrimPrefix(target, "http://"), base64.StdEncoding.EncodeToString([]byte("user:old")))
	if err != nil {
		return nil, err
	}
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		return nil, err
	}
	if method != http.MethodConnect {
		response.Body.Close()
	}
	return response, nil
}

// A connection of an HTTP proxy kept alive between two requests ends with the box: its next request
// was served by the inbound of the closed box, with the users it had, and answered 502 by its closed
// router. A tunnel, which the router has, ends with the connection it was dialed, as before.
func TestKeptAliveConnectionEndsWithBox(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	instance, address := startProxy(t)
	dial := func() (net.Conn, *bufio.Reader) {
		conn, err := net.Dial("tcp", address)
		require.NoError(t, err)
		t.Cleanup(func() { conn.Close() })
		require.NoError(t, conn.SetDeadline(time.Now().Add(20*time.Second)))
		return conn, bufio.NewReader(conn)
	}
	kept, keptReader := dial()
	for range 2 {
		response, err := proxyRequest(kept, keptReader, http.MethodGet, server.URL+"/")
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, response.StatusCode)
	}
	// nothing was sent on this one yet
	silent, silentReader := dial()
	tunnel, tunnelReader := dial()
	response, err := proxyRequest(tunnel, tunnelReader, http.MethodConnect, strings.TrimPrefix(server.URL, "http://"))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode)
	_, err = tunnel.Write([]byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n"))
	require.NoError(t, err)
	response, err = http.ReadResponse(tunnelReader, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, response.StatusCode)

	require.NoError(t, instance.Close())
	response, err = proxyRequest(kept, keptReader, http.MethodGet, server.URL+"/")
	if err == nil {
		t.Fatal("the closed inbound answered ", response.Status)
	}
	require.False(t, E.IsTimeout(err), err)
	for name, reader := range map[string]*bufio.Reader{"silent": silentReader, "tunnel": tunnelReader} {
		_, err = reader.ReadByte()
		require.Error(t, err, name)
		require.False(t, E.IsTimeout(err), name)
	}
	_ = silent
}

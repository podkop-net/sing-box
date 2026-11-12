package clashapi

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

type delayTestOutbound struct {
	adapter.Outbound
	tag string
}

func (o *delayTestOutbound) Tag() string { return o.tag }

func (o *delayTestOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, syscall.ECONNREFUSED
}

type delayTestManager struct {
	adapter.OutboundManager
}

func (m *delayTestManager) Outbounds() []adapter.Outbound { return nil }

// A manual test that fails is a failure with its time, as one of a round: it takes the delay away,
// and what the download test found stays. The block detector reads both.
func TestProxyDelayFailureIsKept(t *testing.T) {
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory("s", &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	history.StoreDownloadResult("s", urltest.DownloadResult{At: time.Now(), Received: 16 << 10, Stopped: true})
	server := &Server{urlTestHistory: history, outbound: &delayTestManager{}}
	before := time.Now()

	request := httptest.NewRequest(http.MethodGet, "/delay?url=https%3A%2F%2Fexample.invalid%2F&timeout=1000", nil)
	request = request.WithContext(context.WithValue(request.Context(), CtxKeyProxy, &delayTestOutbound{tag: "s"}))
	recorder := httptest.NewRecorder()
	getProxyDelay(server)(recorder, request)
	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)

	require.Nil(t, history.LoadURLTestHistory("s"))
	failed, loaded := history.LoadURLTestFailure("s")
	require.True(t, loaded)
	require.False(t, failed.Before(before))
	download, loaded := history.LoadDownloadResult("s")
	require.True(t, loaded)
	require.True(t, download.Stopped)
}

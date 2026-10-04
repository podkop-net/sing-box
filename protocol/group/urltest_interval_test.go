package group

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type testMember struct {
	outbound.Adapter
	dials atomic.Int32
	dial  func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
}

func newTestMember(outboundType, tag string, dial func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)) *testMember {
	return &testMember{Adapter: outbound.NewAdapter(outboundType, tag, []string{N.NetworkTCP, N.NetworkUDP}, nil), dial: dial}
}

func (m *testMember) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	m.dials.Add(1)
	return m.dial(ctx, network, destination)
}

func (m *testMember) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func dialWorking(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

// testURL serves the URL test and counts its requests.
func testURL(t *testing.T, delay time.Duration) (string, *atomic.Int32) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		time.Sleep(delay)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	return server.URL, &requests
}

// testOutboundManager finds the members of a test group by tag.
type testOutboundManager struct {
	adapter.OutboundManager
	members map[string]adapter.Outbound
}

func (m *testOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	member, loaded := m.members[tag]
	return member, loaded
}

// The periodic test runs every interval: this group's own result from the previous round is
// not fresh any more, while a result another group got within this round is.
func TestURLTestFreshness(t *testing.T) {
	link, _ := testURL(t, 0)
	interval := time.Minute
	for _, testCase := range []struct {
		name   string
		age    time.Duration
		tested bool
	}{
		{"own result of the previous round", interval - C.TCPTimeout + time.Second, true},
		{"result of another group in this round", time.Second, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			member := newTestMember(C.TypeVLESS, "member", dialWorking)
			history := urltest.NewHistoryStorage()
			history.StoreURLTestHistory("member", &adapter.URLTestHistory{Time: time.Now().Add(-testCase.age), Delay: 10})
			ctx := service.ContextWithPtr(context.Background(), history)
			manager := &testOutboundManager{members: map[string]adapter.Outbound{"member": member}}
			group, err := NewURLTestGroup(ctx, manager, log.NewNOPFactory().Logger(), []adapter.Outbound{member}, nil, link, "", interval, 50, 0, false)
			require.NoError(t, err)
			_, _ = group.urlTest(ctx, false)
			require.Equal(t, testCase.tested, member.dials.Load() > 0)
		})
	}
}

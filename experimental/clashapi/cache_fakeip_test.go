package clashapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type fakeIPTransportManager struct {
	adapter.DNSTransportManager
	transports []adapter.DNSTransport
}

func (m fakeIPTransportManager) Transports() []adapter.DNSTransport {
	return m.transports
}

// The FakeIP flush resets the store of the FakeIP server, its memory with the cache file:
// the store of this fork answers from memory, a reset of the cache file alone would leave
// the addresses answered.
func TestFlushFakeIPResetsTheStoreInMemory(t *testing.T) {
	t.Parallel()
	ctx := service.ContextWithDefaultRegistry(context.Background())
	logger := log.NewNOPFactory().NewLogger("test")
	cacheFile := cachefile.New(ctx, logger, option.CacheFileOptions{Enabled: true, Path: filepath.Join(t.TempDir(), "cache.db"), StoreFakeIP: true})
	scope := adapter.NewScope(ctx, logger)
	require.NoError(t, cacheFile.Start(adapter.StartStateInitialize, scope))
	service.MustRegister[adapter.CacheFile](ctx, cacheFile)
	inet4Range := badoption.Prefix(netip.MustParsePrefix("198.18.0.0/15"))
	transport, err := fakeip.NewTableTransport(ctx, logger, "fakeip", option.FakeIPDNSServerOptions{Inet4Range: &inet4Range})
	require.NoError(t, err)
	require.NoError(t, transport.Start(adapter.StartStateStart, scope))
	service.MustRegister[adapter.DNSTransportManager](ctx, fakeIPTransportManager{transports: []adapter.DNSTransport{transport}})
	store := transport.(adapter.FakeIPTransport).Store()
	_, isTable := store.(*fakeip.TableStore)
	require.True(t, isTable)

	address, err := store.Create("example.com", false)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		domain, _ := cacheFile.FakeIPLoad(address)
		return domain == "example.com"
	}, 5*time.Second, 5*time.Millisecond)

	recorder := httptest.NewRecorder()
	cacheRouter(ctx).ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/fakeip/flush", nil))
	require.Equal(t, http.StatusNoContent, recorder.Code, recorder.Body.String())
	_, loaded := store.Lookup(address)
	require.False(t, loaded, "the memory is reset")
	_, loaded = cacheFile.FakeIPLoad(address)
	require.False(t, loaded, "and the cache file")
	again, err := store.Create("example.com", false)
	require.NoError(t, err)
	require.NotEqual(t, address, again, "clients may still hold the old address")
	require.NoError(t, scope.Close())
}

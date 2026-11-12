package httpclient

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

type markRecordingDialer struct {
	access   sync.Mutex
	external []bool
}

func (d *markRecordingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.external = append(d.external, interrupt.IsExternalConnectionFromContext(ctx))
	d.access.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

func (d *markRecordingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (d *markRecordingDialer) take() []bool {
	d.access.Lock()
	defer d.access.Unlock()
	external := d.external
	d.external = nil
	return external
}

// What a request's context carries reaches the dialer of every connection made for it:
// the mark of an external connection, by which a group switching members leaves the
// connection alone, is read there. Each case names the transport that dials.
func TestRequestContextReachesDialer(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Proto)
	})
	plain := httptest.NewServer(handler)
	defer plain.Close()
	http1Only := httptest.NewTLSServer(handler)
	defer http1Only.Close()
	http2 := httptest.NewUnstartedServer(handler)
	http2.EnableHTTP2 = true
	http2.StartTLS()
	defer http2.Close()

	tlsConfig, err := tls.NewSTDClient(context.Background(), log.NewNOPFactory().NewLogger("test"), "", option.OutboundTLSOptions{Enabled: true, Insecure: true})
	require.NoError(t, err)

	for _, testCase := range []struct {
		name    string
		link    string
		options option.HTTPClientOptions
		proto   string
		dials   int
	}{
		{name: "plain HTTP", link: plain.URL, proto: "HTTP/1.1", dials: 1},
		{name: "HTTP/2", link: http2.URL, proto: "HTTP/2.0", dials: 1},
		// the HTTP/2 transport dials, finds HTTP/1.1 negotiated and leaves the request to
		// the HTTP/1.1 transport, which dials again
		{name: "HTTP/1.1 after the HTTP/2 attempt", link: http1Only.URL, proto: "HTTP/1.1", dials: 2},
		{name: "HTTP/1.1 by option", link: http1Only.URL, options: option.HTTPClientOptions{Version: 1}, proto: "HTTP/1.1", dials: 1},
	} {
		for _, marked := range []bool{true, false} {
			dialer := &markRecordingDialer{}
			transport, err := newTransport(dialer, tlsConfig, testCase.options)
			require.NoError(t, err, testCase.name)
			ctx := context.Background()
			if marked {
				ctx = interrupt.ContextWithIsExternalConnection(ctx, true)
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, testCase.link, nil)
			require.NoError(t, err, testCase.name)
			response, err := transport.RoundTrip(request)
			require.NoError(t, err, testCase.name)
			proto, err := io.ReadAll(response.Body)
			response.Body.Close()
			require.NoError(t, err, testCase.name)
			require.Equal(t, testCase.proto, string(proto), testCase.name)
			external := dialer.take()
			require.Len(t, external, testCase.dials, testCase.name)
			for _, isExternal := range external {
				require.Equal(t, marked, isExternal, testCase.name)
			}
			transport.Close()
		}
	}
}

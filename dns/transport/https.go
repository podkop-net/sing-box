package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHTTP "github.com/sagernet/sing/protocol/http"

	mDNS "github.com/miekg/dns"
	"golang.org/x/net/http2"
)

const MimeType = "application/dns-message"

var _ adapter.DNSTransport = (*HTTPSTransport)(nil)

func RegisterHTTPS(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteHTTPSDNSServerOptions](registry, C.DNSTypeHTTPS, NewHTTPS)
}

type HTTPSTransport struct {
	dns.TransportAdapter
	logger           logger.ContextLogger
	dialer           N.Dialer
	destination      *url.URL
	headers          http.Header
	transportAccess  sync.Mutex
	transport        *HTTPSTransportWrapper
	transportResetAt time.Time
	// answeredStartAt is the latest start among the answered exchanges, in nanoseconds since
	// createdAt: time.Sub reads the monotonic clock, which a clock set back does not move
	answeredStartAt atomic.Int64
	createdAt       time.Time
}

func NewHTTPS(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteHTTPSDNSServerOptions) (adapter.DNSTransport, error) {
	transportDialer, err := dns.NewRemoteDialer(ctx, options.RemoteDNSServerOptions)
	if err != nil {
		return nil, err
	}
	tlsOptions := common.PtrValueOrDefault(options.TLS)
	tlsOptions.Enabled = true
	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, tlsOptions)
	if err != nil {
		return nil, err
	}
	if len(tlsConfig.NextProtos()) == 0 {
		tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
	}
	headers := options.Headers.Build()
	host := headers.Get("Host")
	if host != "" {
		headers.Del("Host")
	} else {
		if tlsConfig.ServerName() != "" {
			host = tlsConfig.ServerName()
		} else {
			host = options.Server
		}
	}
	destinationURL := url.URL{
		Scheme: "https",
		Host:   host,
	}
	if destinationURL.Host == "" {
		destinationURL.Host = options.Server
	}
	if options.ServerPort != 0 && options.ServerPort != 443 {
		destinationURL.Host = net.JoinHostPort(destinationURL.Host, strconv.Itoa(int(options.ServerPort)))
	}
	path := options.Path
	if path == "" {
		path = "/dns-query"
	}
	err = sHTTP.URLSetPath(&destinationURL, path)
	if err != nil {
		return nil, err
	}
	serverAddr := options.DNSServerAddressOptions.Build()
	if serverAddr.Port == 0 {
		serverAddr.Port = 443
	}
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address: ", serverAddr)
	}
	return NewHTTPSRaw(
		dns.NewTransportAdapterWithRemoteOptions(C.DNSTypeHTTPS, tag, options.RemoteDNSServerOptions),
		logger,
		transportDialer,
		&destinationURL,
		headers,
		serverAddr,
		tlsConfig,
	), nil
}

func NewHTTPSRaw(
	adapter dns.TransportAdapter,
	logger log.ContextLogger,
	dialer N.Dialer,
	destination *url.URL,
	headers http.Header,
	serverAddr M.Socksaddr,
	tlsConfig tls.Config,
) *HTTPSTransport {
	if tlsConfig != nil {
		dialer = tls.NewDialer(dialer, tlsConfig)
	}
	return &HTTPSTransport{
		TransportAdapter: adapter,
		createdAt:        time.Now(),
		logger:           logger,
		dialer:           dialer,
		destination:      destination,
		headers:          headers,
		transport:        NewHTTPSTransportWrapper(dialer, serverAddr, destination),
	}
}

func (t *HTTPSTransport) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return dialer.InitializeDetour(t.dialer)
}

func (t *HTTPSTransport) Close() error {
	t.transportAccess.Lock()
	defer t.transportAccess.Unlock()
	t.transport.CloseIdleConnections()
	t.transport = t.transport.Clone()
	return nil
}

func (t *HTTPSTransport) Reset() {
	t.transportAccess.Lock()
	defer t.transportAccess.Unlock()
	t.transport.CloseIdleConnections()
	t.transport = t.transport.Clone()
}

func (t *HTTPSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	startAt := time.Now()
	response, err := t.exchange(ctx, message)
	if err != nil && errors.Is(err, io.ErrUnexpectedEOF) && ctx.Err() == nil {
		// The server closed its HTTP/2 connection without a GOAWAY while this query was
		// on it, as Quad9 does to busy connections too: x/net fails every query in
		// flight there and asks none of them again. A DNS query may be asked again; the
		// connection is gone, so this goes over a new one. Once: a server that closes the
		// new connection as well is failing.
		if t.logger != nil {
			t.logger.DebugContext(ctx, "connection closed without a GOAWAY, query asked again")
		}
		// what follows compares this query with the others on its connection by when
		// they began, and its connection is now the new one
		startAt = time.Now()
		response, err = t.exchange(ctx, message)
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			// A query that began after this one was answered: the connection is alive
			// and the timeout is about this query alone (a slow upstream for one name).
			// A reset would open a new connection and leave the old one open.
			if t.answeredStartAt.Load() > t.sinceCreated(startAt) {
				return nil, err
			}
			t.transportAccess.Lock()
			defer t.transportAccess.Unlock()
			if t.transportResetAt.After(startAt) {
				return nil, err
			}
			t.transport.CloseIdleConnections()
			t.transport = t.transport.Clone()
			t.transportResetAt = time.Now()
		}
		return nil, err
	}
	for started := t.sinceCreated(startAt); ; {
		latest := t.answeredStartAt.Load()
		if started <= latest || t.answeredStartAt.CompareAndSwap(latest, started) {
			break
		}
	}
	return response, nil
}

// sinceCreated is a time of this transport as nanoseconds since it was made, by the
// monotonic clock.
func (t *HTTPSTransport) sinceCreated(at time.Time) int64 {
	return int64(at.Sub(t.createdAt))
}

func (t *HTTPSTransport) exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	exMessage := *message
	exMessage.Id = 0
	exMessage.Compress = true
	requestBuffer := buf.NewSize(1 + message.Len())
	rawMessage, err := exMessage.PackBuffer(requestBuffer.FreeBytes())
	if err != nil {
		requestBuffer.Release()
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.destination.String(), bytes.NewReader(rawMessage))
	if err != nil {
		requestBuffer.Release()
		return nil, err
	}
	request.Header = t.headers.Clone()
	request.Header.Set("Content-Type", MimeType)
	request.Header.Set("Accept", MimeType)
	t.transportAccess.Lock()
	currentTransport := t.transport
	t.transportAccess.Unlock()
	response, err := currentTransport.RoundTrip(request)
	requestBuffer.Release()
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, E.New("unexpected status: ", response.Status)
	}
	var responseMessage mDNS.Msg
	if response.ContentLength > 0 {
		responseBuffer := buf.NewSize(int(response.ContentLength))
		defer responseBuffer.Release()
		_, err = responseBuffer.ReadFullFrom(response.Body, int(response.ContentLength))
		if err != nil {
			return nil, err
		}
		err = responseMessage.Unpack(responseBuffer.Bytes())
	} else {
		rawMessage, err = io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		err = responseMessage.Unpack(rawMessage)
	}
	if err != nil {
		return nil, err
	}
	return &responseMessage, nil
}

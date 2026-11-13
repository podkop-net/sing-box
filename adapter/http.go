package adapter

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

type HTTPTransport interface {
	http.RoundTripper
	CloseIdleConnections()
	Reset()
}

type HTTPClientManager interface {
	ResolveTransport(ctx context.Context, logger logger.ContextLogger, options option.HTTPClientOptions) (HTTPTransport, error)
	DefaultTransport() HTTPTransport
	ResetNetwork()
}

// HTTPClientFallbacks is an HTTPClientManager that resolves the fallback clients of a client
// (option.HTTPClientOptions.Fallback): those a caller that saw a request fail through the client
// may repeat it through, in their order. The options are those the caller resolved its transport
// from; nil stands for the default client.
type HTTPClientFallbacks interface {
	ResolveFallbacks(options *option.HTTPClientOptions) ([]HTTPFallback, error)
}

// HTTPDownloaders is an HTTPClientManager whose clients may download through several outbounds
// (option.HTTPClientOptions.Outbounds).
type HTTPDownloaders interface {
	// ResolveDownloader is the downloader of the client the options name, or of the default
	// client for nil; nil when that client has no outbounds.
	ResolveDownloader(options *option.HTTPClientOptions) (HTTPDownloader, error)
}

// HTTPDownloader downloads files through the outbounds of a client: in the order of what it
// knows of each for the host of the file, the next one started beside those under way when they
// stall, the first accepted result taken.
type HTTPDownloader interface {
	// Download tries the ways for the host as their order says until accept takes a result of
	// try. accept is called for one result at a time; an error of it fails that way. It returns
	// the way of the accepted result.
	Download(ctx context.Context, host string, try HTTPDownloadTry, accept func(way string, result any) error) (string, error)
	// Ways is the order of the ways for the host, for a caller that downloads by itself, and
	// whether the first two start together (the first failed for the host last time).
	Ways(host string) ([]string, bool)
	// Record takes the result of such a download through a way: err nil when it brought the
	// file, of size bytes in took.
	Record(host string, way string, err error, took time.Duration, bytes int64)
	// Hold keeps the pooled connections of the ways until its CloseIdleConnections: a box
	// registers it with the start of its rule sets (HTTPStartContext).
	Hold() HTTPTransport
}

// HTTPDownloadTry downloads through one way of a downloader with its client. progress is called
// when the headers came (0) and with the size of each part of the body that comes.
type HTTPDownloadTry func(ctx context.Context, way string, client *http.Client, progress func(bytes int)) (any, error)

// HTTPFallback is a fallback client: its tag and its shared transport.
type HTTPFallback struct {
	Tag       string
	Transport HTTPTransport
}

type HTTPStartContext struct {
	access     sync.Mutex
	transports []HTTPTransport
}

func NewHTTPStartContext() *HTTPStartContext {
	return &HTTPStartContext{}
}

func (c *HTTPStartContext) Register(transport HTTPTransport) {
	c.access.Lock()
	defer c.access.Unlock()
	c.transports = append(c.transports, transport)
}

func (c *HTTPStartContext) Close() {
	for _, transport := range c.transports {
		transport.CloseIdleConnections()
	}
}

package adapter

import (
	"context"
	"net/http"
	"sync"

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

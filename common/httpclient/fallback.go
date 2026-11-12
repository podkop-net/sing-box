package httpclient

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.HTTPClientFallbacks = (*Manager)(nil)

// ResolveFallbacks resolves the fallback clients of the client of options, or of the default
// client for nil: the shared transports of the tags its Fallback names, in their order.
func (m *Manager) ResolveFallbacks(options *option.HTTPClientOptions) ([]adapter.HTTPFallback, error) {
	var own string
	var tags []string
	switch {
	case options == nil:
		own = m.defaultTag
		if own == "" {
			return nil, nil
		}
		tags = m.defines[own].Fallback
	case options.Tag != "":
		own = options.Tag
		define, loaded := m.defines[own]
		if !loaded {
			return nil, E.New("http_client not found: ", own)
		}
		tags = define.Fallback
	default:
		tags = options.Fallback
	}
	fallbacks := make([]adapter.HTTPFallback, 0, len(tags))
	for _, tag := range tags {
		if own != "" && tag == own {
			return nil, E.New("http_client[", own, "]: fallback names the client itself")
		}
		sharedTransport, err := m.resolveShared(tag)
		if err != nil {
			return nil, E.Cause(err, "fallback")
		}
		fallbacks = append(fallbacks, adapter.HTTPFallback{Tag: tag, Transport: newSharedRef(sharedTransport.managed, sharedTransport.shared)})
	}
	return fallbacks, nil
}

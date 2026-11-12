package outbound

import (
	"context"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

// What podkop-engine adds to the manager: an outbound built and started outside it takes the
// place of the one of its tag while the box runs (box.UpdateOutbounds). Nothing here starts,
// stops or closes an outbound.

// NewOutbound builds an outbound as Create does, without putting it in the manager.
func (m *Manager) NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) (adapter.Outbound, error) {
	if tag == "" {
		return nil, os.ErrInvalid
	}
	return m.registry.CreateOutbound(ctx, router, logger, tag, outboundType, options)
}

// SwapOutbounds puts each outbound of put in the place of the one of its tag, or after the
// others when its tag is new, and takes out those of the tags in remove. It returns the
// outbounds it replaced or took out. The list and the map are copied, not changed: who read
// them before goes on with what was there. Nothing is changed when a tag is given twice, is
// that of an endpoint, is to be removed and is not there, or is the default outbound's to be
// removed. The default outbound that is replaced is the new one.
func (m *Manager) SwapOutbounds(put []adapter.Outbound, remove []string) ([]adapter.Outbound, error) {
	m.access.Lock()
	defer m.access.Unlock()
	replacing := make(map[string]adapter.Outbound, len(put))
	for _, outbound := range put {
		tag := outbound.Tag()
		if tag == "" {
			return nil, os.ErrInvalid
		}
		if _, given := replacing[tag]; given {
			return nil, E.New("duplicate outbound tag: ", tag)
		}
		if _, isEndpoint := m.endpoint.Get(tag); isEndpoint {
			return nil, E.New("outbound tag is that of an endpoint: ", tag)
		}
		replacing[tag] = outbound
	}
	removing := make(map[string]bool, len(remove))
	for _, tag := range remove {
		if _, given := replacing[tag]; given || removing[tag] {
			return nil, E.New("duplicate outbound tag: ", tag)
		}
		if _, loaded := m.outboundByTag[tag]; !loaded {
			return nil, E.New("outbound not found: ", tag)
		}
		if m.defaultOutbound != nil && m.defaultOutbound.Tag() == tag {
			return nil, E.New("the default outbound cannot be removed: ", tag)
		}
		removing[tag] = true
	}
	outbounds := make([]adapter.Outbound, 0, len(m.outbounds)+len(put))
	outboundByTag := make(map[string]adapter.Outbound, len(m.outboundByTag)+len(put))
	var previous []adapter.Outbound
	for _, outbound := range m.outbounds {
		tag := outbound.Tag()
		if removing[tag] {
			previous = append(previous, outbound)
			continue
		}
		if next, replaced := replacing[tag]; replaced {
			previous = append(previous, outbound)
			outbound = next
		}
		outbounds = append(outbounds, outbound)
		outboundByTag[tag] = outbound
	}
	for _, outbound := range put {
		if _, placed := outboundByTag[outbound.Tag()]; !placed {
			outbounds = append(outbounds, outbound)
			outboundByTag[outbound.Tag()] = outbound
		}
	}
	if m.defaultOutbound != nil {
		if next, replaced := replacing[m.defaultOutbound.Tag()]; replaced {
			m.defaultOutbound = next
		}
	}
	m.outbounds = outbounds
	m.outboundByTag = outboundByTag
	return previous, nil
}

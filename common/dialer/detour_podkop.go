package dialer

import N "github.com/sagernet/sing/common/network"

// current is the outbound of the tag of the detour now, found at every dial: one replaced while
// the box runs (box.UpdateOutbounds) is not kept for good by those that dial through it, as the HTTP
// client of the lists and the DNS servers do (podkop-engine). The outbound found first, which init
// checked, stands while the tag has none.
func (d *DetourDialer) current() N.Dialer {
	if d.detour != "" {
		if outbound, loaded := d.outboundManager.Outbound(d.detour); loaded {
			return outbound
		}
		return d.dialer
	}
	if outbound := d.outboundManager.Default(); outbound != nil {
		return outbound
	}
	return d.dialer
}

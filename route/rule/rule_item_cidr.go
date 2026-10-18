package rule

import (
	"net/netip"
	"slices"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/cidrset"
	E "github.com/sagernet/sing/common/exceptions"

	"go4.org/netipx"
)

var _ RuleItem = (*IPCIDRItem)(nil)

type IPCIDRItem struct {
	ipSet       ipSet
	isSource    bool
	description string
}

// ipSet is what an item asks of its addresses: netipx.IPSet, or a cidrset.Set.
type ipSet interface {
	Contains(netip.Addr) bool
}

func NewIPCIDRItem(isSource bool, prefixStrings []string) (*IPCIDRItem, error) {
	// the set of common/cidrset: the ranges netipx makes of the same list, in a fraction
	// of its memory; a canonical IPv4 prefix is read from its text, any other by netip
	var builder cidrset.Builder
	builder.Grow(len(prefixStrings))
	for i, prefixString := range prefixStrings {
		if from, to, ok := cidrset.Parse4(prefixString); ok {
			builder.Add4(from, to)
			continue
		}
		prefix, err := netip.ParsePrefix(prefixString)
		if err == nil {
			if !builder.AddPrefix(prefix) {
				return newNetipxCIDRItem(isSource, prefixStrings)
			}
			continue
		}
		addr, addrErr := netip.ParseAddr(prefixString)
		if addrErr == nil {
			if !builder.AddAddr(addr) {
				return newNetipxCIDRItem(isSource, prefixStrings)
			}
			continue
		}
		return nil, E.Cause(err, "parse [", i, "]")
	}
	return &IPCIDRItem{
		ipSet:       builder.Set(""),
		isSource:    isSource,
		description: cidrset.Describe(isSource, prefixStrings[:min(3, len(prefixStrings))], len(prefixStrings)),
	}, nil
}

// newNetipxCIDRItem is the item as upstream builds it, for a list cidrset does not take.
func newNetipxCIDRItem(isSource bool, prefixStrings []string) (*IPCIDRItem, error) {
	var builder netipx.IPSetBuilder
	for i, prefixString := range prefixStrings {
		prefix, err := netip.ParsePrefix(prefixString)
		if err == nil {
			builder.AddPrefix(prefix)
			continue
		}
		addr, addrErr := netip.ParseAddr(prefixString)
		if addrErr == nil {
			builder.Add(addr)
			continue
		}
		return nil, E.Cause(err, "parse [", i, "]")
	}
	ipSet, err := builder.IPSet()
	if err != nil {
		return nil, err
	}
	return &IPCIDRItem{
		ipSet:       ipSet,
		isSource:    isSource,
		description: cidrset.Describe(isSource, prefixStrings[:min(3, len(prefixStrings))], len(prefixStrings)),
	}, nil
}

func NewRawIPCIDRItem(isSource bool, ipSet *netipx.IPSet) *IPCIDRItem {
	var description string
	if isSource {
		description = "source_ip_cidr="
	} else {
		description = "ip_cidr="
	}
	description += "<binary>"
	return &IPCIDRItem{
		ipSet:       ipSet,
		isSource:    isSource,
		description: description,
	}
}

// NewCIDRSetItem is the item of a set common/cidrset built of the list of a rule.
func NewCIDRSetItem(isSource bool, set *cidrset.Set) *IPCIDRItem {
	return &IPCIDRItem{
		ipSet:       set,
		isSource:    isSource,
		description: set.String(),
	}
}

// netipxSet is the set of the item as a netipx.IPSet, for a TUN that routes it.
func (r *IPCIDRItem) netipxSet() *netipx.IPSet {
	switch set := r.ipSet.(type) {
	case *netipx.IPSet:
		return set
	case *cidrset.Set:
		ipSet, err := set.IPSet()
		if err == nil {
			return ipSet
		}
	}
	return new(netipx.IPSet)
}

func (r *IPCIDRItem) Match(metadata *adapter.InboundContext) bool {
	if r.isSource || metadata.IPCIDRMatchSource {
		return r.ipSet.Contains(metadata.Source.Addr)
	}
	if metadata.Destination.IsIP() {
		return r.ipSet.Contains(metadata.Destination.Addr)
	}
	if len(metadata.DestinationAddresses) > 0 {
		return slices.ContainsFunc(metadata.DestinationAddresses, r.ipSet.Contains)
	}
	return metadata.IPCIDRAcceptEmpty
}

func (r *IPCIDRItem) String() string {
	return r.description
}

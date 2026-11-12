package option

import "github.com/sagernet/sing/common/json/badoption"

// GroupDNSServerOptions are the options of a DNS server of the type group (podkop-engine,
// dns/transport_group.go): other DNS servers of the box by tag, asked one after another in
// the order of the list ("order", the default) or the fastest first ("fastest").
type GroupDNSServerOptions struct {
	Servers  badoption.Listable[string] `json:"servers,omitempty" reference:"dns_server"`
	Strategy string                     `json:"strategy,omitempty" enum:"order,fastest"`
}

// ProviderDNSServerOptions are the options of a DNS server of the type provider
// (podkop-engine, dns/transport_provider.go): the DNS servers of the internet provider that
// netifd knows. There are none: what to ask is read from the system.
type ProviderDNSServerOptions struct{}

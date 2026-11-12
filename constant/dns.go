package constant

const (
	DefaultDNSTTL = 600
)

type DomainStrategy = uint8

const (
	DomainStrategyAsIS DomainStrategy = iota
	DomainStrategyPreferIPv4
	DomainStrategyPreferIPv6
	DomainStrategyIPv4Only
	DomainStrategyIPv6Only
)

const (
	DNSTypeLegacy      = "legacy"
	DNSTypeUDP         = "udp"
	DNSTypeTCP         = "tcp"
	DNSTypeTLS         = "tls"
	DNSTypeHTTPS       = "https"
	DNSTypeQUIC        = "quic"
	DNSTypeHTTP3       = "h3"
	DNSTypeLocal       = "local"
	DNSTypeHosts       = "hosts"
	DNSTypeFakeIP      = "fakeip"
	DNSTypeDHCP        = "dhcp"
	DNSTypeMDNS        = "mdns"
	DNSTypeTailscale   = "tailscale"
	DNSTypeOpenConnect = "openconnect"
	DNSTypeOpenVPN     = "openvpn"
	// a list of DNS servers asked in order or by speed, and the internet provider's DNS
	// servers that netifd knows (podkop-engine, dns/transport_group.go, dns/transport_provider.go)
	DNSTypeGroup    = "group"
	DNSTypeProvider = "provider"
)

// The strategies of a DNS server group (podkop-engine).
const (
	DNSGroupStrategyOrder   = "order"
	DNSGroupStrategyFastest = "fastest"
)

const (
	DNSProviderAliDNS     = "alidns"
	DNSProviderCloudflare = "cloudflare"
	DNSProviderACMEDNS    = "acmedns"
)

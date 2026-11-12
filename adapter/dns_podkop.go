package adapter

import (
	"net/netip"
	"time"
)

// The state of the DNS servers of the types group and provider, for diagnostics
// (podkop-engine, dns/transport_group.go and dns/transport_provider.go). A program that
// runs the box in its process finds a server by tag through the DNS transport manager of
// the box and asserts these interfaces:
//
//	manager := service.FromContext[adapter.DNSTransportManager](ctx)
//	transport, _ := manager.Transport("dns-server")
//	if group, isGroup := transport.(adapter.DNSGroupTransport); isGroup {
//		state := group.GroupState()
//	}

// DNSGroupTransport is a DNS server of the type group.
type DNSGroupTransport interface {
	DNSTransport
	GroupState() DNSGroupState
}

type DNSGroupState struct {
	Strategy string // "order" or "fastest"
	// SafetyNet: when every member fails with an error, the query is asked of the
	// provider's servers (the provider DNS fallback is enabled and no member is a provider
	// server); SafetyNetAnswer is the last time they answered such a query
	SafetyNet       bool
	SafetyNetAnswer time.Time
	Members         []DNSGroupMemberState // in the order of the configuration
}

type DNSGroupMemberState struct {
	Tag  string
	Type string // "" until the group found its members (box start)
	// SetAside: it failed twice in a row and is only probed in the background, until it
	// answers again
	SetAside bool
	// SmoothedTime is the smoothed time of its answers, 0 when not measured (none yet, or
	// none since the last network reset)
	SmoothedTime time.Duration
	LastAnswer   time.Time // zero when none
	// Answers and Failures count the answers (NOERROR, NXDOMAIN) and failures (errors and
	// timeouts) of every query sent to it, the background copies included, since the start
	Answers  uint64
	Failures uint64
}

// DNSProviderTransport is a DNS server of the type provider.
type DNSProviderTransport interface {
	DNSTransport
	// ProviderServers returns the provider's servers it asks now; when the list is due to be
	// read (never read, or after a network reset), it reads it first, which runs ubus.
	ProviderServers() []DNSProviderServer
}

type DNSProviderServer struct {
	Address netip.AddrPort
	// Device is the device of the uplink a query to it is bound to, "" when sing-box binds
	// its own sockets (auto_detect_interface, default_interface)
	Device string
}

package dns

import (
	"context"
	"encoding/json"
	"maps"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

// The provider's servers for the fallback (podkop-engine).
//
// They are the DNS servers of the OpenWrt interfaces, taken from netifd over ubus:
//
//   - When sing-box binds its sockets to a device (auto_detect_interface or
//     default_interface), the servers of the interfaces on that device: all its traffic
//     leaves there. For DHCP or PPPoE these are the servers of wan and wan6 (or wan_6).
//   - Else the servers of every uplink: each interface that is up and has a default route,
//     tunnels left out (wireguard, openvpn and the like), so a backup modem or a second WAN
//     too. A query to a server of an uplink is bound to the device of that uplink: a
//     provider answers its own customers, and when mwan3 (or anything else) sends the
//     traffic of the router another way, the server of each uplink is still reached through
//     it. An uplink whose provider is down does not answer; another one does.
//
// A LAN with DNS set by hand, an interface without a default route and a tunnel are left
// out. The list belongs to a box (the DNS router makes it): a box that replaces another one
// in the same process, with other settings, reads it again. It is read at the first
// fallback, and again when sing-box resets the network after its default interface changed
// (the DNS router calls forget): another uplink, the WAN down and up, a new PPPoE session.
// It is also read again after none of its servers answered and 30 s after ubus could not be
// asked, in both cases not sooner than 30 s after the last read: each read runs ubus.
//
// The servers are chosen by their answers, as dnsmasq does: the first fallback query goes
// to all of them at once, the first to answer gets the next queries alone, and all of them
// are asked again every 20 s or 50 queries, and as soon as it misses one: an uplink that
// comes back takes over again when it answers first.

const (
	providerRetryAfter  = 30 * time.Second // between reads after ubus could not be asked or no server answered
	providerMax         = 4                // servers of one device
	providerMaxAll      = 8                // servers asked at once
	providerRoundEvery  = 20 * time.Second
	providerRoundAfter  = 50 // queries
	providerBestTimeout = 1500 * time.Millisecond
	providerUbusTimeout = 3 * time.Second
)

var (
	errNoProviders = E.New("no provider DNS on the output device")

	// provider queries have their own sockets: a burst of queries waiting for a silent
	// server must not keep them from the provider. The bound is of the process, not of a box.
	fallbackSocketSlots = make(chan struct{}, 256)

	// the set of a context without a DNS router (providersFrom)
	defaultProviders = newProviderSet()

	// the protocols of netifd that make tunnels, not uplinks of a provider
	tunnelProtocols = []string{"wireguard", "amneziawg", "openvpn", "openconnect", "vpnc", "gre", "gretap", "grev6", "grev6tap", "vti", "vtiv6", "xfrm", "ipip"}
)

func newProviderSet() *providerSet {
	return &providerSet{read: readUbusInterfaces}
}

// providersFrom is the provider set of the box of ctx, which its DNS router registers.
func providersFrom(ctx context.Context) *providerSet {
	if ctx != nil {
		if set := service.FromContext[*providerSet](ctx); set != nil {
			return set
		}
	}
	return defaultProviders
}

type providerSet struct {
	read func(ctx context.Context) ([]netifdInterface, error)

	access  sync.Mutex
	reading bool // one read at a time, outside the lock
	servers []M.Socksaddr
	// devices are the devices of the uplinks the queries to the servers are bound to; a
	// server without one is asked through the dialer of the server (sing-box binds them)
	devices map[M.Socksaddr]string
	device  string // the output device the list is for, "" for every uplink
	readAt  time.Time
	readErr bool        // ubus could not be asked
	stale   bool        // no server answered: the list may have changed
	best    M.Socksaddr // the server that answered last, invalid when none
	uses    int         // queries sent to best alone since all were asked
	roundAt time.Time   // when all were asked
}

// netifdInterface is what the fallback needs of `ubus call network.interface dump`.
type netifdInterface struct {
	Name      string   `json:"interface"`
	Up        bool     `json:"up"`
	Proto     string   `json:"proto"`
	L3Device  string   `json:"l3_device"`
	DNSServer []string `json:"dns-server"`
	Route     []struct {
		Target string `json:"target"`
		Mask   int    `json:"mask"`
		Metric int    `json:"metric"`
	} `json:"route"`
}

func readUbusInterfaces(ctx context.Context) ([]netifdInterface, error) {
	ctx, cancel := context.WithTimeout(ctx, providerUbusTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, "ubus", "call", "network.interface", "dump").Output()
	if err != nil {
		return nil, E.Cause(err, "ubus call network.interface dump")
	}
	var dump struct {
		Interface []netifdInterface `json:"interface"`
	}
	err = json.Unmarshal(output, &dump)
	if err != nil {
		return nil, E.Cause(err, "parse ubus network.interface dump")
	}
	return dump.Interface, nil
}

// known reports whether there are provider servers; it is on the path of every query, so
// a due read runs in the background.
func (p *providerSet) known(ctx context.Context, logger logger.ContextLogger) bool {
	p.access.Lock()
	count := len(p.servers)
	start := p.rereadDue() && !p.reading
	if start {
		p.reading = true
	}
	p.access.Unlock()
	if start {
		go p.refresh(logger, outputDevice(ctx))
	}
	return count > 0
}

func (p *providerSet) rereadDue() bool {
	return p.readAt.IsZero() || ((p.readErr || p.stale) && time.Since(p.readAt) >= providerRetryAfter)
}

// list returns the provider's servers, reading them again when it is due. While another
// query reads them, the servers read before are returned.
func (p *providerSet) list(ctx context.Context, logger logger.ContextLogger) []M.Socksaddr {
	p.access.Lock()
	servers := p.servers
	start := p.rereadDue() && !p.reading
	if start {
		p.reading = true
	}
	p.access.Unlock()
	if !start {
		return servers
	}
	return p.refresh(logger, outputDevice(ctx))
}

func (p *providerSet) refresh(logger logger.ContextLogger, device string) []M.Socksaddr {
	var (
		servers []M.Socksaddr
		devices map[M.Socksaddr]string
		names   []string
	)
	interfaces, err := p.read(context.Background())
	if err == nil {
		servers, devices, names = providersOn(interfaces, device)
	}
	p.access.Lock()
	defer p.access.Unlock()
	p.reading = false
	changed := p.readAt.IsZero() || device != p.device || !slices.Equal(servers, p.servers) || !maps.Equal(devices, p.devices)
	p.servers, p.devices, p.device, p.readAt, p.readErr, p.stale = servers, devices, device, time.Now(), err != nil, false
	if changed {
		p.best = M.Socksaddr{}
		if logger != nil {
			switch {
			case err != nil:
				logger.Warn("no provider DNS for the fallback: ", err)
			case len(servers) == 0 && device != "":
				logger.Warn("no provider DNS for the fallback on ", device)
			case len(servers) == 0:
				logger.Warn("no provider DNS for the fallback: no uplink has DNS servers")
			case device != "":
				logger.Warn("provider DNS for the fallback on ", device, " (", strings.Join(names, ", "), "): ", joinServers(servers))
			default:
				logger.Warn("provider DNS for the fallback, each through its uplink: ", strings.Join(names, "; "))
			}
		}
	}
	return servers
}

// deviceOf is the device a query to a server is bound to, "" for none.
func (p *providerSet) deviceOf(server M.Socksaddr) string {
	p.access.Lock()
	defer p.access.Unlock()
	return p.devices[server]
}

// forget makes the next use read the servers again.
func (p *providerSet) forget() {
	p.access.Lock()
	p.readAt = time.Time{}
	p.best = M.Socksaddr{}
	p.access.Unlock()
}

// noneAnswered makes a later use read the servers again: they may have changed without a
// network reset, as when DHCP hands out other ones. Unlike forget it keeps the time of
// the last read, so that servers that keep refusing do not run ubus at every query.
func (p *providerSet) noneAnswered() {
	p.access.Lock()
	p.stale = true
	p.best = M.Socksaddr{}
	p.access.Unlock()
}

func (p *providerSet) names() string {
	p.access.Lock()
	defer p.access.Unlock()
	return joinServers(p.servers)
}

// pick returns the server to ask alone: the one that answered last, while its turn lasts.
func (p *providerSet) pick(servers []M.Socksaddr) (M.Socksaddr, bool) {
	p.access.Lock()
	defer p.access.Unlock()
	if !p.best.IsValid() || p.uses >= providerRoundAfter || time.Since(p.roundAt) >= providerRoundEvery || !slices.Contains(servers, p.best) {
		return M.Socksaddr{}, false
	}
	p.uses++
	return p.best, true
}

func (p *providerSet) chose(server M.Socksaddr) {
	p.access.Lock()
	p.best, p.uses, p.roundAt = server, 0, time.Now()
	p.access.Unlock()
}

func (p *providerSet) missed(server M.Socksaddr) {
	p.access.Lock()
	if p.best == server {
		p.best = M.Socksaddr{}
	}
	p.access.Unlock()
}

// providersOn returns the DNS servers of the interfaces that are up on device; when device
// is "" (sing-box binds no socket), those of every uplink, each with the device of its
// uplink to bind the queries to, the uplinks in the order of their default routes. The
// names tell the interfaces the servers come from.
func providersOn(interfaces []netifdInterface, device string) (servers []M.Socksaddr, devices map[M.Socksaddr]string, names []string) {
	own := ownAddresses()
	seen := make(map[netip.Addr]bool)
	// the servers of each device: at most providerMax
	counts := make(map[string]int)
	add := func(networkInterface netifdInterface, bind bool) []string {
		var added []string
		for _, server := range networkInterface.DNSServer {
			address, err := netip.ParseAddr(server)
			if err != nil || address.IsLoopback() || address.IsUnspecified() || own[address.Unmap()] {
				continue
			}
			if address.IsLinkLocalUnicast() && address.Zone() == "" {
				address = address.WithZone(networkInterface.L3Device)
			}
			if seen[address] || counts[networkInterface.L3Device] >= providerMax || len(servers) >= providerMaxAll {
				continue
			}
			seen[address] = true
			counts[networkInterface.L3Device]++
			socksaddr := M.SocksaddrFrom(address, 53)
			servers = append(servers, socksaddr)
			if bind {
				if devices == nil {
					devices = make(map[M.Socksaddr]string)
				}
				devices[socksaddr] = networkInterface.L3Device
			}
			added = append(added, address.String())
		}
		return added
	}
	if device != "" {
		for _, networkInterface := range interfaces {
			if networkInterface.Up && networkInterface.L3Device == device && len(networkInterface.DNSServer) > 0 {
				names = append(names, networkInterface.Name)
				add(networkInterface, false)
			}
		}
		return servers, nil, names
	}
	for _, networkInterface := range uplinks(interfaces) {
		if added := add(networkInterface, true); len(added) > 0 {
			names = append(names, networkInterface.Name+" on "+networkInterface.L3Device+": "+strings.Join(added, ", "))
		}
	}
	return servers, devices, names
}

// uplinks are the interfaces that are up, have a device and a default route, and are no
// tunnel, in the order of the metric of their default route (IPv4 first).
func uplinks(interfaces []netifdInterface) []netifdInterface {
	type uplink struct {
		networkInterface netifdInterface
		metric           int
	}
	var found []uplink
	for _, networkInterface := range interfaces {
		if !networkInterface.Up || networkInterface.L3Device == "" || slices.Contains(tunnelProtocols, networkInterface.Proto) {
			continue
		}
		best, isUplink := 0, false
		for _, route := range networkInterface.Route {
			if route.Mask != 0 || (route.Target != "0.0.0.0" && route.Target != "::") {
				continue
			}
			metric := route.Metric
			if route.Target == "::" {
				metric += 1 << 20
			}
			if !isUplink || metric < best {
				best, isUplink = metric, true
			}
		}
		if isUplink {
			found = append(found, uplink{networkInterface, best})
		}
	}
	slices.SortStableFunc(found, func(left uplink, right uplink) int { return left.metric - right.metric })
	result := make([]netifdInterface, len(found))
	for index, item := range found {
		result[index] = item.networkInterface
	}
	return result
}

// outputDevice is the device sing-box binds its sockets to (auto_detect_interface or
// default_interface), "" when it does not bind them.
func outputDevice(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	manager := service.FromContext[adapter.NetworkManager](ctx)
	if manager == nil {
		return ""
	}
	if bind := manager.DefaultOptions().BindInterface; bind != "" {
		return bind
	}
	if manager.AutoDetectInterface() {
		if networkInterface := manager.DefaultNetworkInterface(); networkInterface != nil {
			return networkInterface.Name
		}
	}
	return ""
}

func ownAddresses() map[netip.Addr]bool {
	own := make(map[netip.Addr]bool)
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return own
	}
	for _, interfaceAddress := range addresses {
		prefix, err := netip.ParsePrefix(interfaceAddress.String())
		if err == nil {
			own[prefix.Addr().Unmap()] = true
		}
	}
	return own
}

// exchangeProvider asks the provider's servers from fresh sockets through the server's own
// dialer: the one that answered last, or all of them at once.
func (s *fallbackServer) exchangeProvider(ctx context.Context, baseCtx context.Context, logger logger.ContextLogger, message *mDNS.Msg) (*mDNS.Msg, error) {
	servers := s.providersFor(s.providers.list(baseCtx, logger))
	if len(servers) == 0 {
		return nil, errNoProviders
	}
	ctx, cancel := context.WithTimeout(ctx, fallbackTimeout)
	defer cancel()
	if best, loaded := s.providers.pick(servers); loaded {
		bestCtx, bestCancel := context.WithTimeout(ctx, providerBestTimeout)
		response, err := exchangeFresh(bestCtx, fallbackSocketSlots, s.dialerFor(s.providers.deviceOf(best)), best, message)
		bestCancel()
		if err == nil && response.Rcode != mDNS.RcodeRefused {
			return s.providerAnswered(response), nil
		}
		s.providers.missed(best)
		if ctx.Err() != nil {
			if err == nil {
				err = E.New("refused")
			}
			return nil, E.Cause(err, "provider DNS ", best)
		}
	}
	response, err := s.exchangeAll(ctx, servers, message)
	if err != nil && ctx.Err() == nil {
		s.providers.noneAnswered()
	}
	return response, err
}

// exchangeAll asks all the servers at once: the first answer wins, the other sockets are
// closed with the context.
func (s *fallbackServer) exchangeAll(ctx context.Context, servers []M.Socksaddr, message *mDNS.Msg) (*mDNS.Msg, error) {
	ctx, cancel := context.WithCancel(ctx)
	// the losers end with the context (it closes their sockets); wait for them, so that
	// nothing of this exchange runs on after it returned
	var exchanges sync.WaitGroup
	defer func() {
		cancel()
		exchanges.Wait()
	}()
	type result struct {
		server   M.Socksaddr
		response *mDNS.Msg
		err      error
	}
	results := make(chan result, len(servers))
	for _, server := range servers {
		exchanges.Add(1)
		go func(server M.Socksaddr) {
			defer exchanges.Done()
			response, err := exchangeFresh(ctx, fallbackSocketSlots, s.dialerFor(s.providers.deviceOf(server)), server, message)
			results <- result{server, response, err}
		}(server)
	}
	err := E.New("provider DNS refused")
	for range servers {
		answer := <-results
		if answer.err != nil {
			err = answer.err
			continue
		}
		if answer.response.Rcode == mDNS.RcodeRefused {
			continue
		}
		s.providers.chose(answer.server)
		return s.providerAnswered(answer.response), nil
	}
	return nil, err
}

func (s *fallbackServer) providerAnswered(response *mDNS.Msg) *mDNS.Msg {
	s.access.Lock()
	s.providerFails = 0
	s.access.Unlock()
	capTTL(response, fallbackMaxTTL)
	return response
}

// providersFor leaves the server itself out.
func (s *fallbackServer) providersFor(servers []M.Socksaddr) []M.Socksaddr {
	self := s.options.DNSServerAddressOptions.Build()
	if !self.IsIP() {
		return servers
	}
	var others []M.Socksaddr
	for _, server := range servers {
		if server.Addr.Unmap() != self.Addr.Unmap() {
			others = append(others, server)
		}
	}
	return others
}

func joinServers(servers []M.Socksaddr) string {
	names := make([]string, 0, len(servers))
	for _, server := range servers {
		names = append(names, server.Addr.String())
	}
	return strings.Join(names, ", ")
}

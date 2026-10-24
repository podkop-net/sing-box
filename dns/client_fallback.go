package dns

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

// Fallback to the DNS servers of the internet provider (podkop-engine).
//
// When a DNS server that sing-box reaches directly through the WAN fails to answer
// (timeout, refused or reset connection, TLS or HTTP error), the query is sent to the
// provider's servers: the DNS servers that netifd knows for the output device of sing-box,
// or for every uplink when sing-box binds no socket, each asked through its uplink (see
// client_fallback_provider.go). Setting SING_BOX_DNS_FALLBACK turns this on; the
// init script of podkop-engine does it when podkop is installed.
//
// Which servers qualify is decided once, from the configuration: a plain socket (no
// detour, or a detour to a direct outbound) without dial fields that send it another
// way (bind_interface, routing_mark, bind address, netns), to a public address or a
// domain name. A server behind a proxy, an outbound group or a bound interface (a VPN),
// and a local or private resolver (127.0.0.1, LAN, VPN) never fall back and behave
// exactly as without this code. Routes of the system are not looked at: a server sent
// into a VPN by a route, not by sing-box, looks like any other. The fallback query goes
// through the server's own dialer.
//
// After two failures in a row answered by the provider, the server is set aside: queries
// go straight to the provider, and a copy of one query is sent to the server in the
// background, every 30 s at first and up to every 5 minutes; the first normal answer
// brings it back. A failure counts when the provider resolved the name (NOERROR or
// NXDOMAIN): a name that neither resolves says nothing about the server. Queries that
// fail together are one failure: the second is a query that started after the first was
// counted. A SERVFAIL is retried through the provider as well but does not count
// against the server: it is usually about one domain. When the provider fails to answer
// twice in a row, the fallback is off for that server for a minute. A network reset
// starts the counts over and makes the provider usable again; a server that is set aside
// stays so but is probed with the next query, see reset.
//
// Everything the fallback writes to the log is a warning: whether a server has it, the
// provider's servers and every change of state are there in a log that is not at the
// info level.
var fallbackEnabled = os.Getenv("SING_BOX_DNS_FALLBACK") != ""

const (
	fallbackPrimaryTimeout = 3500 * time.Millisecond
	fallbackTimeout        = 3 * time.Second
	fallbackDownAfter      = 2
	fallbackProbeFirst     = 30 * time.Second
	fallbackProbeMax       = 5 * time.Minute
	fallbackProviderAfter  = 2           // provider failures in a row that switch the fallback off
	fallbackUnusableFor    = time.Minute // then the provider is tried again, as dnscrypt-proxy does
	fallbackMaxTTL         = 60
)

var (
	// not public, besides what netip reports: CGNAT (also Tailscale) and "this network"
	fallbackNonPublic = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("0.0.0.0/8")}
	fallbackLocalTLDs = []string{".localhost", ".local", ".lan", ".home.arpa", ".internal"}
)

type fallbackServer struct {
	options option.RemoteDNSServerOptions

	decideOnce sync.Once
	eligible   bool
	dialer     N.Dialer
	// ctx is the one of the box (decide); bound are the dialers of the server bound to the
	// devices of uplinks (dialerFor)
	ctx   context.Context
	bound map[string]N.Dialer

	access        sync.Mutex
	failures      int
	countedAt     time.Time // the last failure counted or the last network reset
	providerFails int
	down          bool
	probeAt       time.Time
	probeEvery    time.Duration
	unusableUntil time.Time

	providers *providerSet // the box's, shared by all its servers (decide)
}

// newFallbackServer returns the fallback state of a remote server, nil when the fallback
// is not enabled.
func newFallbackServer(options option.RemoteDNSServerOptions) *fallbackServer {
	if !fallbackEnabled {
		return nil
	}
	return &fallbackServer{options: options}
}

func fallbackFor(transport adapter.DNSTransport) *fallbackServer {
	remote, isRemote := transport.(interface{ fallbackState() *fallbackServer })
	if !isRemote {
		return nil
	}
	return remote.fallbackState()
}

// exchangeWithFallback: ctx carries the deadline of the query, baseCtx the services of
// the box.
func exchangeWithFallback(ctx context.Context, baseCtx context.Context, logger logger.ContextLogger, transport adapter.DNSTransport, state *fallbackServer, message *mDNS.Msg) (*mDNS.Msg, error) {
	tag := transport.Tag()
	if !state.decide(baseCtx, logger, tag) {
		return transport.Exchange(ctx, message)
	}
	if state.isDown() {
		if state.probeDue() {
			go probeServer(context.WithoutCancel(ctx), logger, transport, state, message.Copy())
		}
		response, err := state.exchangeProvider(ctx, baseCtx, logger, message)
		if err == nil {
			return response, nil
		}
		// the provider does not answer either: ask the server itself
		if ctx.Err() == nil {
			state.providerFailed(ctx, logger, tag, err)
		}
		return transport.Exchange(ctx, message)
	}
	usable := state.usable(baseCtx, logger)
	startAt := time.Now()
	primaryCtx, cancel := ctx, context.CancelFunc(func() {})
	if usable {
		primaryCtx, cancel = context.WithTimeout(ctx, fallbackPrimaryTimeout)
	}
	response, err := transport.Exchange(primaryCtx, message)
	cancel()
	var rcodeError RcodeError
	if err == nil || errors.As(err, &rcodeError) {
		state.success()
		servfail := (err == nil && response.Rcode == mDNS.RcodeServerFailure) || (err != nil && int(rcodeError) == mDNS.RcodeServerFailure)
		if usable && servfail {
			alternative, altErr := state.exchangeProvider(ctx, baseCtx, logger, message)
			if altErr == nil && (alternative.Rcode == mDNS.RcodeSuccess || alternative.Rcode == mDNS.RcodeNameError) {
				return alternative, nil
			}
		}
		return response, err
	}
	if !usable || ctx.Err() != nil {
		return nil, err // the provider is not used now, or the caller gave the query up
	}
	alternative, altErr := state.exchangeProvider(ctx, baseCtx, logger, message)
	if altErr != nil {
		if ctx.Err() == nil {
			state.providerFailed(ctx, logger, tag, altErr)
		}
		return nil, err
	}
	if alternative.Rcode == mDNS.RcodeSuccess || alternative.Rcode == mDNS.RcodeNameError {
		state.failure(ctx, logger, tag, startAt, err)
	}
	return alternative, nil
}

func probeServer(ctx context.Context, logger logger.ContextLogger, transport adapter.DNSTransport, state *fallbackServer, message *mDNS.Msg) {
	ctx, cancel := context.WithTimeout(ctx, fallbackPrimaryTimeout)
	defer cancel()
	response, err := transport.Exchange(ctx, message)
	if err != nil || response.Rcode == mDNS.RcodeServerFailure {
		return
	}
	state.access.Lock()
	wasDown := state.down
	state.down = false
	state.failures = 0
	state.access.Unlock()
	if wasDown && logger != nil {
		logger.WarnContext(ctx, "server ", transport.Tag(), " answers again, provider DNS no longer used")
	}
}

// decide tells once whether the fallback applies to the server; ctx carries the services
// of the box.
func (s *fallbackServer) decide(ctx context.Context, logger logger.ContextLogger, tag string) bool {
	s.decideOnce.Do(func() {
		var reason string
		if ctx == nil {
			reason = "no context"
		} else {
			reason = fallbackExclusion(ctx, s.options)
		}
		if reason == "" {
			dialer, err := NewRemoteDialer(ctx, s.options)
			if err != nil {
				reason = err.Error()
			} else {
				s.dialer, s.ctx = dialer, ctx
				s.eligible = true
				if s.providers == nil {
					s.providers = providersFrom(ctx)
				}
				s.providers.list(ctx, logger) // at once: the first query may need them
			}
		}
		if logger == nil {
			return
		}
		if s.eligible {
			logger.Warn("server ", tag, " falls back to provider DNS when it fails")
		} else {
			logger.Warn("no provider DNS fallback for server ", tag, ": ", reason)
		}
	})
	return s.eligible
}

// fallbackExclusion returns why a server does not qualify, "" when it does.
func fallbackExclusion(ctx context.Context, options option.RemoteDNSServerOptions) string {
	if options.Legacy {
		return "legacy server format"
	}
	if field := specialDialField(options.DialerOptions); field != "" {
		return field
	}
	if options.Detour != "" {
		outbounds := service.FromContext[adapter.OutboundManager](ctx)
		if outbounds == nil {
			return "detour " + options.Detour
		}
		outbound, loaded := outbounds.Outbound(options.Detour)
		if !loaded {
			return "detour " + options.Detour + " not found"
		}
		direct, isDirect := outbound.(interface{ DialerOptions() option.DialerOptions })
		if outbound.Type() != C.TypeDirect || !isDirect {
			return "detour through " + outbound.Type() + " outbound " + options.Detour
		}
		if field := specialDialField(direct.DialerOptions()); field != "" {
			return field + " of outbound " + options.Detour
		}
	}
	server := options.DNSServerAddressOptions.Build()
	if server.IsIP() && !publicAddress(server.Addr) {
		return "local or private address " + server.Addr.String()
	}
	if server.IsDomain() && localName(server.Fqdn) {
		return "local name " + server.Fqdn
	}
	return ""
}

// specialDialField names a dial field that sends a socket another way than a plain one
// through the system routes. Fields known to leave the route alone are cleared first, so
// any other one, including a field added by a later sing-box, counts as special.
func specialDialField(options option.DialerOptions) string {
	switch {
	case options.BindInterface != "":
		return "bind_interface " + options.BindInterface
	case options.RoutingMark != 0:
		return "routing_mark"
	case options.Inet4BindAddress != nil || options.Inet6BindAddress != nil:
		return "bind address"
	case options.NetNs != "":
		return "netns " + options.NetNs
	}
	options.Detour = "" // checked by the caller
	options.BindAddressNoPort = false
	options.ReuseAddr = false
	options.ConnectTimeout = 0
	options.TCPFastOpen = false
	options.TCPMultiPath = false
	options.DisableTCPKeepAlive = false
	options.TCPKeepAlive = 0
	options.TCPKeepAliveInterval = 0
	options.UDPFragment = nil
	options.UDPFragmentDefault = false
	options.DomainResolver = nil
	options.FallbackDelay = 0
	options.DomainStrategy = 0 //nolint:staticcheck
	if !reflect.DeepEqual(options, option.DialerOptions{}) {
		return "dial fields"
	}
	return ""
}

func publicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() {
		return false // loopback, link-local, multicast, unspecified, RFC 1918, ULA
	}
	for _, prefix := range fallbackNonPublic {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func localName(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if !strings.Contains(name, ".") {
		return true // "localhost", "router"
	}
	for _, suffix := range fallbackLocalTLDs {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// dialerFor is the dialer of a query to a server of the provider: the server's own, or for
// a server of an uplink one like it bound to the device of that uplink, made once. Only a
// plain socket qualifies (fallbackExclusion): the detour to a direct outbound is left out.
func (s *fallbackServer) dialerFor(device string) N.Dialer {
	if device == "" || s.ctx == nil {
		return s.dialer
	}
	s.access.Lock()
	defer s.access.Unlock()
	if dialer, made := s.bound[device]; made {
		return dialer
	}
	options := s.options
	options.DialerOptions.Detour = ""
	options.DialerOptions.BindInterface = device
	dialer, err := NewRemoteDialer(s.ctx, options)
	if err != nil {
		dialer = s.dialer
	}
	if s.bound == nil {
		s.bound = make(map[string]N.Dialer)
	}
	s.bound[device] = dialer
	return dialer
}

func (s *fallbackServer) isDown() bool {
	s.access.Lock()
	defer s.access.Unlock()
	return s.down
}

// usable reports whether the provider may be used now: it has not stopped answering
// lately and is known.
func (s *fallbackServer) usable(ctx context.Context, logger logger.ContextLogger) bool {
	s.access.Lock()
	blocked := time.Now().Before(s.unusableUntil)
	s.access.Unlock()
	return !blocked && s.providers.known(ctx, logger)
}

// probeDue reserves the next background check of a server that is set aside.
func (s *fallbackServer) probeDue() bool {
	s.access.Lock()
	defer s.access.Unlock()
	now := time.Now()
	if !s.down || now.Before(s.probeAt) {
		return false
	}
	s.probeAt = now.Add(s.probeEvery)
	s.probeEvery = min(s.probeEvery*2, fallbackProbeMax)
	return true
}

func (s *fallbackServer) success() {
	s.access.Lock()
	s.failures = 0
	s.access.Unlock()
}

// failure counts a failure of the server answered by the provider, for a query sent at
// startAt. Queries that were on their way when the last failure was counted are part of
// the same event, such as a closed connection they shared, and are not counted again.
func (s *fallbackServer) failure(ctx context.Context, logger logger.ContextLogger, tag string, startAt time.Time, cause error) {
	s.access.Lock()
	if startAt.Before(s.countedAt) {
		s.access.Unlock()
		return
	}
	s.countedAt = time.Now()
	s.failures++
	if s.down || s.failures < fallbackDownAfter {
		s.access.Unlock()
		return
	}
	s.down = true
	s.probeEvery = fallbackProbeFirst
	s.probeAt = time.Now().Add(s.probeEvery)
	s.access.Unlock()
	if logger != nil {
		// the logger formats only strings, numbers, errors and Stringers
		logger.WarnContext(ctx, "server ", tag, " failed ", fallbackDownAfter, " times in a row (", cause, "), answering from provider DNS ", s.providers.names(), " until it is back")
	}
}

// reset forgets what was learned on the network that sing-box has just left: the DNS
// router calls it when sing-box resets the network. The provider is usable again and the
// failure counts start over; queries on their way fail with the connections that the
// reset closes and count nothing. A server that is set aside stays so, since asking a
// dead server first would cost the next queries its timeout, but it is probed with the
// next query.
func (s *fallbackServer) reset() {
	s.access.Lock()
	s.failures = 0
	s.countedAt = time.Now()
	s.providerFails = 0
	s.unusableUntil = time.Time{}
	if s.down {
		s.probeAt = s.countedAt
		s.probeEvery = fallbackProbeFirst
	}
	s.access.Unlock()
}

// providerFailed stops using the provider: for a while when it fails to answer twice in a
// row, until it is listed again when there is none.
func (s *fallbackServer) providerFailed(ctx context.Context, logger logger.ContextLogger, tag string, cause error) {
	if errors.Is(cause, errNoProviders) {
		s.access.Lock()
		s.down = false
		s.failures = 0
		s.access.Unlock()
		return
	}
	s.access.Lock()
	s.providerFails++
	if s.providerFails < fallbackProviderAfter {
		s.access.Unlock()
		return
	}
	s.providerFails = 0
	s.down = false
	s.failures = 0
	s.unusableUntil = time.Now().Add(fallbackUnusableFor)
	s.access.Unlock()
	if logger != nil {
		logger.WarnContext(ctx, "provider DNS does not answer for server ", tag, " (", cause, "), no fallback for it for ", fallbackUnusableFor)
	}
}

// capTTL keeps provider answers short-lived, so that the server takes over again soon
// after it is back.
func capTTL(message *mDNS.Msg, maxTTL uint32) {
	for _, section := range [][]mDNS.RR{message.Answer, message.Ns, message.Extra} {
		for _, record := range section {
			if record.Header().Rrtype == mDNS.TypeOPT {
				continue
			}
			if record.Header().Ttl > maxTTL {
				record.Header().Ttl = maxTTL
			}
		}
	}
}

func (c *Client) exchangeTransport(ctx context.Context, transport adapter.DNSTransport, message *mDNS.Msg) (*mDNS.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if state := fallbackFor(transport); state != nil {
		return exchangeWithFallback(ctx, c.ctx, c.logger, transport, state, message)
	}
	return transport.Exchange(ctx, message)
}

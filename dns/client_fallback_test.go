package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

func TestFallbackExclusion(t *testing.T) {
	t.Parallel()
	harmless := option.DialerOptions{
		DomainResolver:     &option.DomainResolveOptions{Server: "bootstrap-dns-server"},
		ConnectTimeout:     badoption.Duration(time.Second),
		TCPFastOpen:        true,
		UDPFragmentDefault: true,
	}
	for _, test := range []struct {
		server   string
		dial     option.DialerOptions
		legacy   bool
		excluded bool
	}{
		{server: "77.88.8.8"},
		{server: "2606:4700:4700::1111"},
		{server: "dns.google", dial: harmless},
		{server: "127.0.0.10", excluded: true},
		{server: "::1", excluded: true},
		{server: "::ffff:127.0.0.1", excluded: true},
		{server: "192.168.1.10", excluded: true},
		{server: "10.8.0.1", excluded: true},
		{server: "fd00::53", excluded: true},
		{server: "100.100.100.100", excluded: true},
		{server: "169.254.169.254", excluded: true},
		{server: "localhost", excluded: true},
		{server: "adguard.lan", excluded: true},
		{server: "1.1.1.1", dial: option.DialerOptions{BindInterface: "wg0"}, excluded: true},
		{server: "1.1.1.1", dial: option.DialerOptions{RoutingMark: 0x100}, excluded: true},
		{server: "1.1.1.1", dial: option.DialerOptions{NetNs: "vpn"}, excluded: true},
		{server: "1.1.1.1", dial: option.DialerOptions{ProtectPath: "/protect"}, excluded: true}, // a field not known as harmless
		{server: "1.1.1.1", legacy: true, excluded: true},
	} {
		options := option.RemoteDNSServerOptions{
			RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{DialerOptions: test.dial, Legacy: test.legacy},
			DNSServerAddressOptions:  option.DNSServerAddressOptions{Server: test.server},
		}
		reason := fallbackExclusion(context.Background(), options)
		if (reason != "") != test.excluded {
			t.Errorf("%s %+v: excluded %v (%q), want %v", test.server, test.dial, reason != "", reason, test.excluded)
		}
	}
}

// A dump of `ubus call network.interface dump` with a tunnel, a LAN with DNS set by hand
// and a backup modem next to the WAN.
const testUbusDump = `{"interface":[
{"interface":"awg","up":true,"proto":"amneziawg","l3_device":"awg0","dns-server":["10.9.0.1"],"route":[{"target":"0.0.0.0","mask":0,"metric":5}]},
{"interface":"lan","up":true,"l3_device":"br-lan","dns-server":["1.1.1.1"],"route":[]},
{"interface":"loopback","up":true,"l3_device":"lo","dns-server":[],"route":[]},
{"interface":"modem","up":true,"l3_device":"wwan0","dns-server":["100.64.5.1"],"route":[{"target":"0.0.0.0","mask":0,"metric":20}]},
{"interface":"wan","up":true,"l3_device":"wan0","dns-server":["10.99.0.53","10.99.0.54","127.0.0.1","10.99.0.53"],"route":[{"target":"0.0.0.0","mask":0,"metric":0}]},
{"interface":"wan6","up":true,"l3_device":"wan0","dns-server":["fe80::1","2a00::53","2a00::54"],"route":[{"target":"::","mask":0,"metric":512}]},
{"interface":"wg0","up":false,"dns-server":["10.8.0.1"]}]}`

func TestProvidersOn(t *testing.T) {
	t.Parallel()
	var dump struct {
		Interface []netifdInterface `json:"interface"`
	}
	if err := json.Unmarshal([]byte(testUbusDump), &dump); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		device, wantNames, wantServers, wantDevices string
	}{
		// sing-box binds its sockets to a device: its servers, asked as the server is
		{"wan0", "wan; wan6", "10.99.0.53, 10.99.0.54, fe80::1%wan0, 2a00::53", ""}, // at most 4
		{"wwan0", "modem", "100.64.5.1", ""},
		{"eth9", "", "", ""},
		// it binds none: every uplink, each server bound to its uplink, the uplinks by the
		// metric of their default route; the tunnel and the interfaces without a default
		// route are left out
		{"", "wan on wan0: 10.99.0.53, 10.99.0.54; modem on wwan0: 100.64.5.1; wan6 on wan0: fe80::1%wan0, 2a00::53",
			"10.99.0.53, 10.99.0.54, 100.64.5.1, fe80::1%wan0, 2a00::53", "wan0, wan0, wwan0, wan0, wan0"},
	} {
		servers, devices, names := providersOn(dump.Interface, test.device)
		var bound []string
		for _, server := range servers {
			if device := devices[server]; device != "" {
				bound = append(bound, device)
			}
		}
		if strings.Join(names, "; ") != test.wantNames || joinServers(servers) != test.wantServers || strings.Join(bound, ", ") != test.wantDevices {
			t.Errorf("device %q: got %q %q %q, want %q %q %q", test.device, strings.Join(names, "; "), joinServers(servers), strings.Join(bound, ", "),
				test.wantNames, test.wantServers, test.wantDevices)
		}
	}
}

// testResolver answers A queries with 1.2.3.4, or with the rcode given; a negative rcode
// means no answer at all.
func testResolver(t *testing.T, rcode int) M.Socksaddr {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			if rcode < 0 {
				continue
			}
			var query mDNS.Msg
			if query.Unpack(buffer[:n]) != nil {
				continue
			}
			response := new(mDNS.Msg)
			response.SetRcode(&query, rcode)
			if rcode == mDNS.RcodeSuccess {
				response.Answer = []mDNS.RR{&mDNS.A{Hdr: mDNS.RR_Header{Name: query.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 300}, A: net.IPv4(1, 2, 3, 4)}}
			}
			packed, _ := response.Pack()
			conn.WriteTo(packed, addr)
		}
	}()
	return M.SocksaddrFromNet(conn.LocalAddr())
}

// All servers are asked at once, the first real answer wins and is asked alone next time.
func TestExchangeAll(t *testing.T) {
	t.Parallel()
	silent, refused, good := testResolver(t, -1), testResolver(t, mDNS.RcodeRefused), testResolver(t, mDNS.RcodeSuccess)
	servers := []M.Socksaddr{silent, refused, good}
	state := &fallbackServer{dialer: N.SystemDialer, providers: &providerSet{}}
	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	response, err := state.exchangeAll(ctx, servers, message)
	if err != nil || len(response.Answer) != 1 || response.Answer[0].Header().Ttl != fallbackMaxTTL { // capped from 300
		t.Fatalf("got %v, %v", response, err)
	}
	if best, loaded := state.providers.pick(servers); !loaded || best != good {
		t.Fatalf("next query goes to %v (%v), want %v", best, loaded, good)
	}
	for i := 1; i < providerRoundAfter; i++ {
		state.providers.pick(servers)
	}
	if _, loaded := state.providers.pick(servers); loaded {
		t.Error("all servers are not asked again after 50 queries")
	}
	_, err = state.exchangeAll(ctx, []M.Socksaddr{silent, refused}, message)
	if err == nil {
		t.Error("no error when no server answered")
	}
}

func TestCapTTL(t *testing.T) {
	t.Parallel()
	message := new(mDNS.Msg)
	message.Answer = []mDNS.RR{&mDNS.A{Hdr: mDNS.RR_Header{Name: "a.", Rrtype: mDNS.TypeA, Ttl: 3600}}}
	message.SetEdns0(1232, false)
	capTTL(message, fallbackMaxTTL)
	if ttl := message.Answer[0].Header().Ttl; ttl != fallbackMaxTTL {
		t.Errorf("answer TTL %d, want %d", ttl, fallbackMaxTTL)
	}
	if message.IsEdns0() == nil || message.IsEdns0().UDPSize() != 1232 {
		t.Error("OPT record changed")
	}
}

// The logger formats only strings, numbers, errors and Stringers and panics on anything
// else: every message of the fallback goes through a real one here. It is at the warn
// level: a message of the fallback written below that level would be missing.
func TestFallbackLogs(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now(), DisableColors: true}, &output, "", nil, false)
	factory.SetLevel(log.LevelWarn)
	if err := factory.Start(); err != nil {
		t.Fatal(err)
	}
	logger := factory.NewLogger("dns")
	var dump struct {
		Interface []netifdInterface `json:"interface"`
	}
	if err := json.Unmarshal([]byte(testUbusDump), &dump); err != nil {
		t.Fatal(err)
	}
	readDump := func(ctx context.Context) ([]netifdInterface, error) { return dump.Interface, nil }

	// the decision, with the provider's servers read for it
	qualifies := &fallbackServer{
		options:   option.RemoteDNSServerOptions{DNSServerAddressOptions: option.DNSServerAddressOptions{Server: "77.88.8.8"}},
		providers: &providerSet{read: readDump},
	}
	if !qualifies.decide(context.Background(), logger, "dns-server") {
		t.Error("a server at a public address does not qualify")
	}
	(&fallbackServer{}).decide(nil, logger, "dns-server") //nolint:staticcheck
	(&providerSet{read: readDump}).refresh(logger, "eth9")
	(&providerSet{read: readDump}).refresh(logger, "wan0")
	(&providerSet{read: func(ctx context.Context) ([]netifdInterface, error) { return nil, E.New("no ubus in tests") }}).refresh(logger, "")

	// the server fails, the provider fails, the server is back
	state := &fallbackServer{providers: &providerSet{
		servers: []M.Socksaddr{M.ParseSocksaddrHostPort("10.99.0.53", 53), M.ParseSocksaddrHostPort("fe80::1%eth1", 53)},
		readAt:  time.Now(),
	}}
	for i := 0; i < fallbackDownAfter; i++ {
		state.failure(context.Background(), logger, "dns-server", time.Now(), E.New("timeout"))
	}
	state.providerFailed(context.Background(), logger, "dns-server", errNoProviders) // silent
	for i := 0; i < fallbackProviderAfter; i++ {
		state.providerFailed(context.Background(), logger, "dns-server", E.New("timeout"))
	}
	if state.usable(context.Background(), logger) {
		t.Error("fallback still usable after the provider failed")
	}
	transport, setAside, _ := newFallbackTest()
	setAside.down = true
	probeServer(context.Background(), logger, transport, setAside, freshTestQuery())

	for _, message := range []string{
		"provider DNS for the fallback on wan0 (wan, wan6): 10.99.0.53, 10.99.0.54, fe80::1%wan0, 2a00::53",
		"provider DNS for the fallback, each through its uplink: wan on wan0: 10.99.0.53, 10.99.0.54; modem on wwan0: 100.64.5.1; wan6 on wan0: fe80::1%wan0, 2a00::53",
		"server dns-server falls back to provider DNS when it fails",
		"no provider DNS fallback for server dns-server: no context",
		"no provider DNS for the fallback on eth9",
		"no provider DNS for the fallback: no ubus in tests",
		"failed 2 times in a row (timeout), answering from provider DNS 10.99.0.53, fe80::1%eth1 until it is back",
		"provider DNS does not answer for server dns-server (timeout), no fallback for it for 1m0s",
		"server dns-server answers again, provider DNS no longer used",
	} {
		if !strings.Contains(output.String(), message) {
			t.Errorf("missing %q in:\n%s", message, output.String())
		}
	}
}

// recordingDialer dials as the system does and tells which servers it was asked for.
type recordingDialer struct {
	N.Dialer
	access sync.Mutex
	asked  []string
}

func (d *recordingDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	d.access.Lock()
	d.asked = append(d.asked, destination.String())
	d.access.Unlock()
	return d.Dialer.ListenPacket(ctx, destination)
}

func (d *recordingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.access.Lock()
	d.asked = append(d.asked, destination.String())
	d.access.Unlock()
	return d.Dialer.DialContext(ctx, network, destination)
}

func (d *recordingDialer) told() []string {
	d.access.Lock()
	defer d.access.Unlock()
	return slices.Clone(d.asked)
}

// A server of an uplink is asked through the dialer bound to the device of that uplink, a
// server without one through the dialer of the server.
func TestProviderOfAnUplinkThroughIt(t *testing.T) {
	t.Parallel()
	ofUplink, ofServer := testResolver(t, mDNS.RcodeSuccess), testResolver(t, -1)
	own, bound := &recordingDialer{Dialer: N.SystemDialer}, &recordingDialer{Dialer: N.SystemDialer}
	state := &fallbackServer{
		dialer: own,
		ctx:    context.Background(),
		bound:  map[string]N.Dialer{"wan9": bound},
		providers: &providerSet{
			servers: []M.Socksaddr{ofUplink, ofServer},
			devices: map[M.Socksaddr]string{ofUplink: "wan9"},
			readAt:  time.Now(),
		},
	}
	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := state.exchangeAll(ctx, state.providers.servers, message); err != nil {
		t.Fatal(err)
	}
	if got := bound.told(); len(got) != 1 || got[0] != ofUplink.String() {
		t.Errorf("the dialer of wan9 was asked for %v, want %v", got, ofUplink)
	}
	if got := own.told(); len(got) != 1 || got[0] != ofServer.String() {
		t.Errorf("the dialer of the server was asked for %v, want %v", got, ofServer)
	}
	if state.dialerFor("") != own {
		t.Error("a server without a device is not asked through the dialer of the server")
	}
}

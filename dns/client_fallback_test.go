package dns

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"

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

func TestReadNameservers(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "resolv.conf.auto")
	content := "# Interface wan\nnameserver 127.0.0.1\nnameserver 77.88.8.8\nnameserver 192.168.1.1\n" +
		"nameserver fe80::1%eth1\nnameserver 0.0.0.0\nnameserver 10.0.0.1\nnameserver 10.0.0.2\nsearch lan\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	servers := readNameservers(path, M.ParseSocksaddrHostPort("77.88.8.8", 53))
	want := []string{"192.168.1.1:53", "[fe80::1%eth1]:53", "10.0.0.1:53"}
	if len(servers) != len(want) {
		t.Fatalf("got %v, want %v", servers, want)
	}
	for i := range want {
		if servers[i].String() != want[i] {
			t.Errorf("server %d: got %s, want %s", i, servers[i], want[i])
		}
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
// else: every message of the fallback goes through a real one here.
func TestFallbackLogs(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	factory := log.NewDefaultFactory(context.Background(), log.Formatter{BaseTime: time.Now(), DisableColors: true}, &output, "", nil, false)
	factory.SetLevel(log.LevelTrace)
	if err := factory.Start(); err != nil {
		t.Fatal(err)
	}
	logger := factory.NewLogger("dns")
	state := &fallbackServer{
		providers: []M.Socksaddr{M.ParseSocksaddrHostPort("10.99.0.53", 53), M.ParseSocksaddrHostPort("fe80::1%eth1", 53)},
		readAt:    time.Now(),
	}
	for i := 0; i < fallbackDownAfter; i++ {
		state.failure(context.Background(), logger, "dns-server", E.New("timeout"))
	}
	state.providerFailed(context.Background(), logger, "dns-server", errNoProviders) // silent
	for i := 0; i < fallbackProviderAfter; i++ {
		state.providerFailed(context.Background(), logger, "dns-server", E.New("timeout"))
	}
	if state.usable() {
		t.Error("fallback still usable after the provider failed")
	}
	(&fallbackServer{}).decide(nil, logger, "dns-server") //nolint:staticcheck
	for _, message := range []string{
		"failed 2 times in a row (timeout), answering from provider DNS 10.99.0.53:53, [fe80::1%eth1]:53 until it is back",
		"provider DNS does not answer for server dns-server (timeout), no fallback for it for 1m0s",
		"no provider DNS fallback for server dns-server: no context",
	} {
		if !strings.Contains(output.String(), message) {
			t.Errorf("missing %q in:\n%s", message, output.String())
		}
	}
}

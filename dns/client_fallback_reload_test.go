package dns

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
)

// boundNetwork is a network manager that binds the sockets of sing-box to a device, as
// default_interface does; nothing else of it is asked here.
type boundNetwork struct {
	adapter.NetworkManager
	device string
}

func (n boundNetwork) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{BindInterface: n.device}
}

func (n boundNetwork) AutoDetectInterface() bool { return false }

// Two boxes one after another in one process (a reload with other settings) have a list of
// the provider's servers each: the first, which binds no socket, every uplink; the second,
// which binds its sockets to the modem (wwan0), the servers of the modem alone.
func TestFallbackProvidersAfterReload(t *testing.T) {
	var dump struct {
		Interface []netifdInterface `json:"interface"`
	}
	if err := json.Unmarshal([]byte(testUbusDump), &dump); err != nil {
		t.Fatal(err)
	}
	read := func(ctx context.Context) ([]netifdInterface, error) { return dump.Interface, nil }
	box := func(network adapter.NetworkManager) context.Context {
		ctx := service.ContextWithDefaultRegistry(context.Background())
		if network != nil {
			service.MustRegister[adapter.NetworkManager](ctx, network)
		}
		// as the DNS router of the box registers it
		service.MustRegister[*providerSet](ctx, &providerSet{read: read})
		return ctx
	}
	first := box(nil)
	if got := joinServers(providersFrom(first).list(first, nil)); got != "10.99.0.53, 10.99.0.54, 100.64.5.1, fe80::1%wan0, 2a00::53" {
		t.Fatalf("the first box: %q", got)
	}
	second := box(boundNetwork{device: "wwan0"})
	if providersFrom(second) == providersFrom(first) {
		t.Fatal("the boxes share a list")
	}
	if got := joinServers(providersFrom(second).list(second, nil)); got != "100.64.5.1" {
		t.Fatalf("the second box, bound to wwan0, asks %q", got)
	}
}

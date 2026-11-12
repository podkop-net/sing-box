//go:build podkop_slim

package include

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/experimental/deprecated"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// newBox creates (and closes) an instance from a configuration, as `sing-box check` does.
func newBox(content string) error {
	ctx := Context(service.ContextWith(context.Background(), deprecated.NewStderrManager(log.StdLogger())))
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(content))
	if err != nil {
		return err
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return err
	}
	return instance.Close()
}

const (
	testUUID      = `"uuid": "6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11"`
	testServer    = `"server": "127.0.0.1", "server_port": 1`
	testServerTLS = testServer + `, "tls": {"enabled": true, "server_name": "example.com"}`
)

// The types podkop writes: a configuration like the one it generates must load.
func TestPodkopConfigurationLoads(t *testing.T) {
	err := newBox(`{
		"dns": {"servers": [
			{"type": "udp", "tag": "udp", "server": "127.0.0.1"},
			{"type": "tls", "tag": "dot", "server": "127.0.0.1"},
			{"type": "https", "tag": "doh", "server": "127.0.0.1"},
			{"type": "fakeip", "tag": "fakeip", "inet4_range": "198.18.0.0/15"}
		]},
		"inbounds": [
			{"type": "tproxy", "tag": "tproxy-in", "listen": "127.0.0.1", "listen_port": 0},
			{"type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 0},
			{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
		],
		"outbounds": [
			{"type": "direct", "tag": "direct-out"},
			{"type": "socks", "tag": "socks-out", ` + testServer + `},
			{"type": "shadowsocks", "tag": "ss-out", ` + testServer + `, "method": "aes-128-gcm", "password": "p"},
			{"type": "trojan", "tag": "trojan-out", ` + testServerTLS + `, "password": "p"},
			{"type": "vless", "tag": "vless-out", ` + testServerTLS + `, ` + testUUID + `},
			{"type": "hysteria2", "tag": "hy2-out", ` + testServerTLS + `, "password": "p"},
			{"type": "tuic", "tag": "tuic-out", ` + testServerTLS + `, ` + testUUID + `},
			{"type": "selector", "tag": "select", "outbounds": ["direct-out", "vless-out"]},
			{"type": "block", "tag": "block-out"},
			{"type": "http", "tag": "http-out", ` + testServer + `},
			{"type": "urltest", "tag": "auto", "outbounds": ["vless-out", "hy2-out"]}
		]
	}`)
	require.NoError(t, err)
}

// The types neither podkop-engine nor podkop-engine-full has fail with a message.
func TestPodkopSlimStubs(t *testing.T) {
	for _, testCase := range []struct {
		config  string
		message string
	}{
		{`{"inbounds": [{"type": "vless", "listen": "127.0.0.1", "listen_port": 0}]}`, "vless inbound is not included in this build (podkop_slim)"},
		{`{"inbounds": [{"type": "hysteria2", "listen": "127.0.0.1", "listen_port": 0}]}`, "hysteria2 inbound is not included in this build (podkop_slim)"},
		{`{"inbounds": [{"type": "tun"}]}`, "tun inbound is not included in this build (podkop_slim)"},
		{`{"dns": {"servers": [{"type": "quic", "tag": "doq", "server": "127.0.0.1"}]}}`, "quic DNS server is not included in this build (podkop_slim)"},
		{`{"services": [{"type": "ssm-api", "servers": {"/": "ss-in"}}]}`, "ssm-api service is not included in this build (podkop_slim)"},
	} {
		err := newBox(testCase.config)
		require.ErrorContains(t, err, testCase.message, testCase.config)
	}
}

// The outbounds of podkop-engine-full: stubs in podkop-engine, real in podkop-engine-full
// (a real constructor may still reject the test options, but never with a stub message).
func TestPodkopFullOutbounds(t *testing.T) {
	for _, outbound := range []string{
		`{"type": "snell", ` + testServer + `, "psk": "p", "version": 4}`,
		`{"type": "vmess", ` + testServer + `, ` + testUUID + `}`,
		`{"type": "naive", ` + testServerTLS + `, "username": "u", "password": "p"}`,
		`{"type": "tor"}`,
		`{"type": "ssh", ` + testServer + `, "user": "u", "password": "p"}`,
		`{"type": "shadowtls", ` + testServerTLS + `, "version": 3, "password": "p"}`,
		`{"type": "anytls", ` + testServerTLS + `, "password": "p"}`,
		`{"type": "hysteria", ` + testServerTLS + `, "up_mbps": 10, "down_mbps": 10}`,
	} {
		err := newBox(`{"outbounds": [` + outbound + `]}`)
		if podkopFull {
			if err != nil {
				require.NotContains(t, err.Error(), "(podkop_slim)", outbound)
			}
		} else {
			require.ErrorContains(t, err, "is not included in this build (podkop_slim), install podkop-engine-full", outbound)
		}
	}
}

// naive is real only with with_naive_outbound (cronet exists for some architectures only).
func TestPodkopNaiveOutbound(t *testing.T) {
	err := newBox(`{"outbounds": [{"type": "naive", ` + testServerTLS + `, "username": "u", "password": "p"}]}`)
	if !podkopFull {
		require.ErrorContains(t, err, "naive outbound is not included in this build (podkop_slim)")
	} else if err != nil {
		require.ErrorContains(t, err, "rebuild with -tags with_naive_outbound")
	}
}

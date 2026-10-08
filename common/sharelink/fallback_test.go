package sharelink

import (
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

const fallbackBase = "vless://" + testUUID + "@example.org:443?security=tls&type=ws&host=h.example.org"

// Options by their paths: the value takes the type the option has.
func TestOptionPaths(t *testing.T) {
	t.Parallel()
	content, warnings := decodeJSON(t, fallbackBase+
		"&sb.tls.fragment=1&sb.tls.record_fragment=false&sb.tls.fragment_fallback_delay=500ms&sb.tls.min_version=1.3"+
		"&sb.tls.cipher_suites=TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256&sb.tls.alpn=%5B%22h2%22%5D"+
		"&sb.multiplex.enabled=true&sb.multiplex.protocol=h2mux&sb.multiplex.max_connections=4&sb.multiplex.padding=1"+
		"&sb.multiplex.brutal=%7B%22enabled%22%3Atrue%2C%22up_mbps%22%3A50%2C%22down_mbps%22%3A100%7D"+
		"&sb.tcp_fast_open=1&sb.connect_timeout=5s&sb.network=tcp&sb.transport.headers.User-Agent=curl%2F8&sb.transport.max_early_data=2048"+
		"&sb.tls.server_name=0123")
	require.JSONEq(t, `{"type":"vless","server":"example.org","server_port":443,"uuid":"`+testUUID+`","network":"tcp","tcp_fast_open":true,"connect_timeout":"5s",
		"tls":{"enabled":true,"server_name":"0123","alpn":["h2"],"min_version":"1.3","cipher_suites":["TLS_AES_128_GCM_SHA256","TLS_CHACHA20_POLY1305_SHA256"],
		"fragment":true,"record_fragment":false,"fragment_fallback_delay":"500ms","utls":{"enabled":true,"fingerprint":"chrome"}},
		"multiplex":{"enabled":true,"protocol":"h2mux","max_connections":4,"padding":true,"brutal":{"enabled":true,"up_mbps":50,"down_mbps":100}},
		"transport":{"type":"ws","headers":{"Host":"h.example.org","User-Agent":"curl/8"},"max_early_data":2048}}`, content)
	require.Empty(t, warnings)

	// what the outbound of the type has, and only that
	content, _ = decodeJSON(t, "ss://"+b64url("aes-256-gcm:p")+"@example.org:8388?sb.udp_over_tcp=true&sb.multiplex.enabled=1&sb.plugin=obfs-local")
	require.JSONEq(t, `{"type":"shadowsocks","server":"example.org","server_port":8388,"method":"aes-256-gcm","password":"p","plugin":"obfs-local","udp_over_tcp":true,"multiplex":{"enabled":true}}`, content)
	content, _ = decodeJSON(t, "hysteria2://p@example.org?sb.hop_interval=30s&sb.obfs.type=salamander&sb.obfs.password=x&sb.tls.ech.enabled=1")
	require.JSONEq(t, `{"type":"hysteria2","server":"example.org","server_port":443,"hop_interval":"30s","obfs":{"type":"salamander","password":"x"},"password":"p","tls":{"enabled":true,"ech":{"enabled":true}}}`, content)

	// a path wins over what the link says otherwise, and says so
	content, warnings = decodeJSON(t, fallbackBase+"&sni=a.example.org&sb.tls.server_name=b.example.org&sb.tls.utls.fingerprint=firefox")
	require.Contains(t, content, `"server_name":"b.example.org"`)
	require.Contains(t, content, `"fingerprint":"firefox"`)
	require.Len(t, warnings, 2)
	require.Contains(t, warnings[0], "sb.tls.server_name replaces what the link sets otherwise")
	// the same value is no news
	_, warnings = decodeJSON(t, fallbackBase+"&sni=a.example.org&sb.tls.server_name=a.example.org")
	require.Empty(t, warnings)

	// a group that is set and not switched on
	content, warnings = decodeJSON(t, "vless://"+testUUID+"@example.org:443?sb.multiplex.protocol=smux&sb.tls.fragment=1")
	require.Contains(t, content, `"multiplex":{"protocol":"smux"}`)
	require.Len(t, warnings, 2)
	require.Contains(t, strings.Join(warnings, "\n"), "multiplex has options and is not enabled (sb.multiplex.enabled=1)")
	require.Contains(t, strings.Join(warnings, "\n"), "tls has options and is not enabled (sb.tls.enabled=1)")
}

// The names other clients use for options of sing-box.
func TestOptionAliases(t *testing.T) {
	t.Parallel()
	content, warnings := decodeJSON(t, fallbackBase+"&tfo=1&tls_fragment=true&tls_record_fragment=0&mux_protocol=h2mux&mux_max_streams=8&brutal_up_mbps=10&mux=true")
	require.JSONEq(t, `{"type":"vless","server":"example.org","server_port":443,"uuid":"`+testUUID+`","tcp_fast_open":true,
		"tls":{"enabled":true,"fragment":true,"record_fragment":false,"utls":{"enabled":true,"fingerprint":"chrome"}},
		"multiplex":{"protocol":"h2mux","max_streams":8,"brutal":{"up_mbps":10}},
		"transport":{"type":"ws","headers":{"Host":"h.example.org"}}}`, content)
	text := strings.Join(warnings, "\n")
	require.Contains(t, text, "mux is not supported and is ignored")
	require.Contains(t, text, "multiplex has options and is not enabled")
	require.Contains(t, text, "multiplex.brutal has options and is not enabled")
	require.Len(t, warnings, 3)

	// a path wins over a name of another client
	content, _ = decodeJSON(t, fallbackBase+"&tcp-fast-open=1&sb.tcp_fast_open=0")
	require.Contains(t, content, `"tcp_fast_open":false`)
	// a name for an option the outbound does not have is ignored, with a warning
	content, warnings = decodeJSON(t, "vless://"+testUUID+"@example.org:443?uot=1")
	require.NotContains(t, content, "udp_over_tcp")
	require.Len(t, warnings, 1)
	require.Contains(t, warnings[0], "uot is not an option of this outbound and is ignored")
	// the schemes that read the name themselves go on doing so
	content, warnings = decodeJSON(t, "socks5://127.0.0.1:1080?uot=1")
	require.Contains(t, content, `"udp_over_tcp":true`)
	require.Empty(t, warnings)
}

// What is not for a link to set, what this sing-box does not have, and what does not fit.
func TestOptionRefusals(t *testing.T) {
	t.Parallel()
	for parameter, id := range map[string]string{
		"sb.detour=other":                           "sb-denied",
		"sb.domain_resolver=local":                  "sb-denied",
		"sb.domain_resolver.server=local":           "sb-denied",
		"sb.bind_interface=eth0":                    "sb-denied",
		"sb.inet4_bind_address=192.0.2.1":           "sb-denied",
		"sb.routing_mark=1":                         "sb-denied",
		"sb.network_strategy=fallback":              "sb-denied",
		"sb.domain_strategy=ipv4_only":              "sb-denied",
		"sb.tls.certificate_path=%2Fetc%2Fpasswd":   "sb-denied",
		"sb.tls.client_key_path=%2Fetc%2Fkey":       "sb-denied",
		"sb.tls.ech.config_path=%2Ftmp%2Fx":         "sb-denied",
		"sb.tls.kernel_tx=1":                        "sb-denied",
		"sb.realm.server_url=https%3A%2F%2Fx":       "sb-unknown",
		"sb.tls.ech.pq_signature_schemes_enabled=1": "sb-denied",
		"sb.type=direct":                            "sb-denied",
		"sb.tag=x":                                  "sb-denied",
		"sb.server=evil.example.org":                "sb-denied",
		"sb.server_port=1":                          "sb-denied",
		"SB.Detour=other":                           "sb-denied",
		"sb.no_such_option=1":                       "sb-unknown",
		"sb.tls.no_such_option=1":                   "sb-unknown",
		"sb.tls.alpn.first=h2":                      "sb-unknown",
		"sb.=1":                                     "sb-unknown",
		// a name that grows when lowered: found by the fuzzer
		"SB.%C4%B0=1":                       "sb-unknown",
		"sb.tls..fragment=1":                "sb-unknown",
		"sb.tls.fragment=maybe":             "sb-value",
		"sb.multiplex.max_connections=many": "sb-value",
		"sb.connect_timeout=soon":           "sb-value",
		"sb.multiplex=on":                   "sb-value",
	} {
		require.Equal(t, id, refusalID(t, fallbackBase+"&"+parameter), parameter)
	}
	// a secret in a value that does not fit is not repeated
	_, _, err := Decode(fallbackBase + "&sb.connect_timeout=" + url.QueryEscape("vless://secret@host"))
	require.Error(t, err)
	require.NotContains(t, err.Error(), "secret")
}

func optionLeaves(valueType reflect.Type, path string, denied string, leaves map[string]string, depth int) {
	for valueType.Kind() == reflect.Pointer {
		valueType = valueType.Elem()
	}
	if denied != "" || valueType.Kind() != reflect.Struct || depth > 8 || (path != "" && readsItself(valueType) && len(jsonFields(valueType)) == 0) {
		class := "sb"
		if denied != "" {
			class = "denied: " + denied
		}
		leaves[path] = class
		return
	}
	fields := jsonFields(valueType)
	if len(fields) == 0 {
		leaves[path] = "sb"
		return
	}
	for name, candidates := range fields {
		for _, candidate := range candidates {
			reason := denied
			if reason == "" {
				reason = deniedOption(name, &candidate.field)
			}
			if reason == "" && path == "" && linkOptions[name] {
				reason = "the link"
			}
			optionLeaves(candidate.field.Type, strings.TrimPrefix(path+"."+name, "."), reason, leaves, depth+1)
		}
	}
}

// Every option of every outbound a link makes is either for a link to set, by its path,
// or denied, with the reason. The list is kept per line of sing-box: an option that
// appears there after a rebase fails this test until somebody has looked at it.
func TestEveryOptionHasALinkForm(t *testing.T) {
	line := "1.13"
	if _, has := reflect.TypeOf(option.Hysteria2OutboundOptions{}).FieldByName("BBRProfile"); has {
		line = "1.14"
	}
	var lines []string
	for outboundType, optionsType := range optionTypes {
		leaves := make(map[string]string)
		optionLeaves(optionsType, "", "", leaves, 0)
		require.NotEmpty(t, leaves, outboundType)
		for path, class := range leaves {
			lines = append(lines, outboundType+" "+path+" "+class)
			if strings.HasSuffix(path, "_path") && !strings.HasSuffix(path, "tcp_multi_path") {
				require.True(t, strings.HasPrefix(class, "denied"), "%s %s: a file", outboundType, path)
			}
		}
	}
	sort.Strings(lines)
	got := strings.Join(lines, "\n") + "\n"
	file := "testdata/options-" + line + ".txt"
	want, err := os.ReadFile(file)
	if err != nil || string(want) != got {
		t.Logf("the options of this line, for %s:\n==== BEGIN OPTIONS\n%s==== END OPTIONS", file, got)
		t.Fatalf("%s is not the list of options of this line (see the log for the list)", file)
	}
	// a path of the list that is for a link to set is taken by the decoder
	require.Contains(t, got, C.TypeVLESS+" tls.fragment sb\n")
	require.Contains(t, got, C.TypeVLESS+" detour denied: another object\n")
}

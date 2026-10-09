package sharelink

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// What the second review of the decoder showed.

// A parameter name with the "amp;" of a link copied out of HTML is the name without it,
// in what it sets and in what is said of it: a path of an option is applied without a
// word, and one a link may not set is refused as any other.
func TestParameterNamesFromHTML(t *testing.T) {
	t.Parallel()
	content, warnings := decodeJSON(t, policyBase+"security=tls&amp;sb.tls.min_version=1.3&AMP;TFO=1&amp;fp=firefox")
	require.Contains(t, content, `"min_version":"1.3"`)
	require.Contains(t, content, `"tcp_fast_open":true`)
	require.Contains(t, content, `"fingerprint":"firefox"`)
	require.Empty(t, warnings)

	require.Equal(t, "sb-denied", refusalID(t, policyBase+"security=tls&amp;sb.detour=other"))
	require.Equal(t, "sb-unknown", refusalID(t, policyBase+"security=tls&amp;sb.no_such_option=1"))
	_, warnings = decodeJSON(t, policyBase+"security=tls&amp;NoSuchName=1")
	require.Equal(t, []string{"NoSuchName is not supported and is ignored"}, warnings)
}

// What stands in the place of a parameter name may be anything, another link included.
// Such a parameter is left out, and no message repeats it.
func TestParameterNamesThatAreNone(t *testing.T) {
	t.Parallel()
	const canary = "CANARY0f6d2c"
	for name, parameter := range map[string]string{
		"another link":      "vless://" + canary + "@h.example.org:443?type=ws",
		"several lines":     "sb.tls.alpn%0Aerror%3A%20" + canary + "=h2",
		"a path with space": "sb.transport.headers.X%20" + canary + "=1",
		"a long one":        strings.Repeat("a", 129) + canary + "=1",
		// a name that grows when lowered: found by the fuzzer
		"not ASCII": "SB.%C4%B0=1",
	} {
		outbound, warnings, err := Decode(policyBase + "security=tls&" + parameter + "&fp=safari")
		require.NoError(t, err, name)
		require.Equal(t, "safari", optionsOf[option.OutboundTLSOptionsContainer](t, outbound).TLS.UTLS.Fingerprint, name)
		require.Equal(t, []string{"a link parameter whose name is not a name is ignored"}, warnings, name)
	}
	// the names every scheme reads, and the paths of options, are names
	_, warnings := decodeJSON(t, policyBase+"security=tls&type=ws&allowInsecure=1&packet-encoding=xudp&x_padding_bytes=1&sb.transport.headers.X-Forwarded-For=h")
	require.Empty(t, warnings)
	require.True(t, plainName("sb.transport.download.tls.reality.public_key"))
	require.False(t, plainName(""))
}

// The keys and the values of the JSON in extra are as free a text as the names of
// parameters: what is not a name is not repeated.
func TestExtraIsNotRepeated(t *testing.T) {
	t.Parallel()
	const canary = "CANARY0f6d2c"
	for _, key := range []string{"vless://" + canary + "@h.example.org:443", `a\nerror:` + canary} {
		_, warnings := transportOf(t, xhttpLink(`{"`+key+`":1,"future":3}`, uriComponent, ""))
		require.Equal(t, []string{"extra: future is not supported and is ignored", "extra: a key that is not a name is ignored"}, warnings, key)
	}
	for _, extra := range []string{
		`{"downloadSettings":{"address":"a","port":1,"network":"x ` + canary + `"}}`,
		`{"downloadSettings":{"address":"a","port":1,"security":"x\n` + canary + `"}}`,
	} {
		_, _, err := Decode(xhttpLink(extra, uriComponent, ""))
		require.Error(t, err, extra)
		require.NotContains(t, err.Error(), strings.ToLower(canary), extra)
		require.NotContains(t, err.Error(), canary, extra)
	}
	_, _, err := Decode(xhttpLink(`{"downloadSettings":{"address":"a","port":1,"network":"kcp"}}`, uriComponent, ""))
	require.ErrorContains(t, err, "downloadSettings: unsupported network: kcp")
	_, warnings := transportOf(t, xhttpLink(`{"headers":{"Host":"other.example.org"}}`, uriComponent, ""))
	require.Equal(t, []string{"extra: the Host header is ignored, the host of the link is used: cdn.example.org"}, warnings)
}

// A list of one is the one: a path that sets what the link has set already replaces
// nothing.
func TestPathRepeatsWhatTheLinkSets(t *testing.T) {
	t.Parallel()
	_, warnings := decodeJSON(t, policyBase+"security=tls&alpn=h2&sb.tls.alpn=h2")
	require.Empty(t, warnings)
	_, warnings = decodeJSON(t, policyBase+"security=tls&alpn=h2&sb.tls.alpn=h2,http/1.1")
	require.Equal(t, []string{"sb.tls.alpn replaces what the link sets otherwise"}, warnings)
}

// The pause between the pieces of a fragmented ClientHello is slept through whatever
// happens to the connection: a link does not set it. The name another client has for it
// is ignored, and the link works with the pause sing-box has by default.
func TestFragmentDelayIsNotForALink(t *testing.T) {
	t.Parallel()
	require.Equal(t, "sb-denied", refusalID(t, policyBase+"security=tls&sb.tls.fragment=1&sb.tls.fragment_fallback_delay=87600h"))
	require.Equal(t, "sb-denied", refusalID(t, xhttpLink(`{"downloadSettings":{"address":"a","port":1,"security":"tls"}}`, uriComponent, "&sb.transport.download.tls.fragment_fallback_delay=1s")))
	content, warnings := decodeJSON(t, policyBase+"security=tls&tls_fragment=1&tls_fragment_fallback_delay=87600h")
	require.Contains(t, content, `"fragment":true`)
	require.NotContains(t, content, "fragment_fallback_delay")
	require.Equal(t, []string{"tls_fragment_fallback_delay is not supported and is ignored"}, warnings)
}

// The security of a VMess link as the client of Xray reads it: any name other than the
// two ciphers is auto. Its server has refused none, zero and aes-128-cfb since 2026, and
// every VMess server takes what auto chooses.
func TestVMessSecurity(t *testing.T) {
	t.Parallel()
	json := func(security string) string {
		return "vmess://" + b64(`{"add":"example.org","port":"443","id":"`+testUUID+`","net":"ws","tls":"tls","scy":"`+security+`"}`)
	}
	for _, security := range []string{"none", "zero", "aes-128-cfb", "ZERO"} {
		for _, link := range []string{json(security), "vmess://" + testUUID + "@example.org:443?security=tls&encryption=" + security} {
			outbound, warnings, err := Decode(link)
			require.NoError(t, err, link)
			require.Equal(t, "auto", optionsOf[option.VMessOutboundOptions](t, outbound).Security, link)
			require.Equal(t, []string{"the VMess security: " + strings.ToLower(security) + " is read as auto, as Xray does: its server refuses any other"}, warnings, link)
		}
	}
	for security, written := range map[string]string{"": "auto", "auto": "auto", "aes-128-gcm": "aes-128-gcm", "chacha20-poly1305": "chacha20-poly1305", "AES-128-GCM": "aes-128-gcm"} {
		outbound, warnings, err := Decode(json(security))
		require.NoError(t, err, security)
		require.Equal(t, written, optionsOf[option.VMessOutboundOptions](t, outbound).Security, security)
		require.Empty(t, warnings, security)
	}
	// what is not a name is not repeated
	_, warnings, err := Decode(json("CANARY 0f6d2c"))
	require.NoError(t, err)
	require.Equal(t, []string{"the VMess security is read as auto, as Xray does: its server refuses any other"}, warnings)
	// the option of sing-box is set by its path
	outbound, warnings, err := Decode("vmess://" + testUUID + "@example.org:443?security=tls&sb.security=zero")
	require.NoError(t, err)
	require.Equal(t, "zero", optionsOf[option.VMessOutboundOptions](t, outbound).Security)
	require.Equal(t, []string{"sb.security replaces what the link sets otherwise"}, warnings)
}

// A flow and the type of a transport set by their paths are any text: a refusal does not
// repeat them as they are.
func TestRefusalsOfWhatPathsSet(t *testing.T) {
	t.Parallel()
	const canary = "CANARY0f6d2c"
	for link, id := range map[string]string{
		policyBase + "security=tls&type=ws&sb.flow=AAA%0A" + canary:                                   "flow",
		policyBase + "security=tls&sb.flow=" + canary + "%20x":                                        "flow",
		policyBase + "sb.flow=xtls-rprx-vision":                                                       "flow-no-tls",
		policyBase + "security=tls&type=ws&sb.flow=xtls-rprx-vision":                                  "flow-transport",
		policyBase + "security=tls&flow=xtls-rprx-vision&sb.transport.type=httpupgrade":               "flow-transport",
		policyBase + "security=tls&type=ws&sb.transport.type=x%20" + canary + "&sb.transport.path=/p": "",
	} {
		_, _, err := Decode(link)
		require.Error(t, err, link)
		require.NotContains(t, err.Error(), canary, link)
		require.NotContains(t, err.Error(), "\n", link)
		if id != "" {
			require.Equal(t, id, refusalID(t, link), link)
		}
	}
	_, _, err := Decode(policyBase + "security=tls&type=ws&sb.flow=xtls-rprx-vision")
	require.ErrorContains(t, err, "flow xtls-rprx-vision is not supported over the ws transport")
}

// The ranges of ports as sing-box reads them: without its first port a range begins at
// 0, without its last one it ends at 65535. The bound is on how many ports a list names.
func TestOpenEndedPortRanges(t *testing.T) {
	t.Parallel()
	for value, ports := range map[string]string{
		"20000%3A":             `"server_ports":["20000:"]`,
		"%3A3000":              `"server_ports":[":3000"]`,
		"1000%3A2000,30000%3A": `"server_ports":["1000:2000","30000:"]`,
		"1%3A65535":            `"server_ports":["1:65535"]`,
	} {
		content, _ := decodeJSON(t, "hysteria2://p@example.org:443?sb.server_ports="+value)
		require.Contains(t, content, ports, value)
	}
	require.Equal(t, "ports", refusalID(t, "hysteria2://p@example.org:443?sb.server_ports=%3A,1%3A"))
	require.Equal(t, "ports", refusalID(t, "hysteria2://p@example.org:443?sb.server_ports=1%3A,1%3A"))
	_, _, err := Decode("hysteria2://p@example.org:443?sb.server_ports=3000%3A2000")
	require.ErrorContains(t, err, "invalid port in the list of ports")
}

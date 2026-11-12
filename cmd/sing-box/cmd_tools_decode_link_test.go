package main

import (
	"bytes"
	"encoding/base64"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/sharelink"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// The contract of "tools decode-link" that scripts rely on: the exit status
// and what goes where.
func TestDecodeLinkCommand(t *testing.T) {
	const link = "vless://6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11@example.org:443?type=xhttp&security=tls&path=%2Fa&mode=packet-up"
	run := func(input string, args ...string) (int, string, string) {
		var output, errorOutput bytes.Buffer
		status := decodeLink(args, strings.NewReader(input), &output, &errorOutput)
		return status, output.String(), errorOutput.String()
	}
	for name, test := range map[string]struct {
		input string
		args  []string
	}{
		"argument":           {"", []string{link}},
		"standard input":     {link + "\n", nil},
		"blank lines, CRLF":  {"\n\r\n" + link + "\r\n\n", nil},
		"a byte order mark":  {"\ufeff" + link, nil},
		"argument wins":      {"vless://ignored\n", []string{link}},
		"with a warning too": {"", []string{link + "&pinSHA256=x&mux=1"}},
	} {
		status, output, errorOutput := run(test.input, test.args...)
		require.Zero(t, status, name)
		var outbound map[string]any
		require.NoError(t, json.Unmarshal([]byte(output), &outbound), name)
		require.Equal(t, "vless", outbound["type"], name)
		require.Equal(t, "xhttp", outbound["transport"].(map[string]any)["type"], name)
		for _, line := range strings.Split(strings.TrimSpace(errorOutput), "\n") {
			if line != "" {
				require.True(t, strings.HasPrefix(line, "warning: "), "%s: %q", name, line)
			}
		}
		if name == "with a warning too" {
			require.Equal(t, 2, strings.Count(errorOutput, "warning: "), errorOutput)
		} else {
			require.Empty(t, errorOutput, name)
		}
	}
	for name, test := range map[string]struct {
		input string
		args  []string
		say   string
	}{
		"unsupported":         {"", []string{"vless://u@example.org:443?type=kcp"}, "error: the mKCP transport is not supported\n"},
		"refused by xhttp":    {"", []string{strings.Replace(link, "mode=packet-up", "mode=stream-up", 1) + "&extra=%7B%22uplinkHTTPMethod%22%3A%22GET%22%7D"}, "error: xhttp: "},
		"flow over xhttp":     {"", []string{link + "&flow=xtls-rprx-vision"}, "error: flow xtls-rprx-vision is not supported over the xhttp transport\n"},
		"no link":             {"\n\n", nil, "error: no link\n"},
		"empty argument":      {"", []string{""}, "error: no link\n"},
		"two links on input":  {link + "\n" + link + "\n", nil, "error: more than one link\n"},
		"two links on a line": {"", []string{link + " " + link}, "error: "},
	} {
		status, output, errorOutput := run(test.input, test.args...)
		require.Equal(t, decodeLinkExitBadLink, status, name)
		require.Empty(t, output, name)
		require.True(t, strings.HasPrefix(errorOutput, test.say), "%s: %q", name, errorOutput)
		require.Equal(t, 1, strings.Count(errorOutput, "\n"), name)
		require.NotContains(t, errorOutput, "6f1c9a0e", name)
	}
	// an xhttp link whose options pass the check must not crash the command
	status, _, _ := run("", link+"&extra=%7B%22xmux%22%3A%7B%22maxConnections%22%3A2%7D%7D")
	require.Zero(t, status)
}

// A link is somebody else's text: the command reads no file for it, and what it says of
// an outbound that cannot be built is one line that does not quote the link.
func TestDecodeLinkReadsNoFile(t *testing.T) {
	const marker = "MARKER-0f6d2c-not-a-certificate"
	file := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(file, []byte(marker+"\n"), 0o600))
	base := "vless://6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11@example.org:443?security=tls&sni=example.org"
	for name, parameter := range map[string]string{
		"a group of options as JSON":   "sb.tls=" + url.QueryEscape(`{"enabled":true,"certificate_path":"`+file+`"}`),
		"the ECH options as JSON":      "sb.tls.ech=" + url.QueryEscape(`{"enabled":true,"config_path":"`+file+`"}`),
		"the option by its path":       "sb.tls.certificate_path=" + url.QueryEscape(file),
		"the client key by its path":   "sb.tls.client_key_path=" + url.QueryEscape(file),
		"a certificate that is no PEM": "cert=" + url.QueryEscape(marker+"\n"+marker),
	} {
		var output, errorOutput bytes.Buffer
		status := decodeLink([]string{base + "&" + parameter}, strings.NewReader(""), &output, &errorOutput)
		require.Equal(t, decodeLinkExitBadLink, status, name)
		require.Empty(t, output.String(), name)
		require.NotContains(t, errorOutput.String(), marker, name)
		require.True(t, strings.HasPrefix(errorOutput.String(), "error: "), name)
		require.Equal(t, 1, strings.Count(errorOutput.String(), "\n"), name)
	}
	// the plugin of Shadowsocks has an option that names a file
	for name, link := range map[string]string{
		"the plugin of the link":       "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@example.org:443?plugin=" + url.QueryEscape("v2ray-plugin;tls;cert="+file),
		"the plugin options by a path": "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@example.org:443?sb.plugin=v2ray-plugin&sb.plugin_opts=" + url.QueryEscape("tls;cert="+file),
	} {
		var output, errorOutput bytes.Buffer
		status := decodeLink([]string{link}, strings.NewReader(""), &output, &errorOutput)
		require.Equal(t, decodeLinkExitBadLink, status, name)
		require.Empty(t, output.String(), name)
		require.Contains(t, errorOutput.String(), "not for a link to set", name)
		require.NotContains(t, errorOutput.String(), marker, name)
	}
	// and no secret of the link in what the outbound itself says
	require.Equal(t, "invalid ...", plainMessage("invalid 6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11:\n\nmore", []string{"6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11"}))
}

// An error is one line, and says nothing of what the link keeps secret, whoever wrote
// it: the decoder, or the outbound of sing-box when it is built.
func TestDecodeLinkErrorsAreOneLine(t *testing.T) {
	const canary = "CANARY0f6d2c"
	const uuid = "6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11"
	for name, link := range map[string]string{
		"tuic, a user that is no UUID":           "tuic://" + canary + ":" + canary + "@example.org:443?alpn=h3",
		"shadowsocks, no method":                 "ss://" + canary + "@example.org:443",
		"shadowsocks, an unknown method":         "ss://" + base64.StdEncoding.EncodeToString([]byte("no-such-method:"+canary)) + "@example.org:443",
		"shadowsocks 2022, a key of no length":   "ss://" + base64.StdEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:"+canary)) + "@example.org:443",
		"hysteria2, an unknown obfuscation":      "hysteria2://" + canary + "@example.org:443?obfs=no-such&obfs-password=" + canary,
		"reality, a key that is none":            "vless://" + uuid + "@example.org:443?security=reality&pbk=" + canary + "&sid=01",
		"reality, a short id too long":           "vless://" + uuid + "@example.org:443?security=reality&pbk=YBZ6SAP7KfiD5YJiyAGvD49eNYW-f-7IlhMarfyy4k0&sid=0123456789abcdef0123",
		"a certificate that is none":             "trojan://" + canary + "@example.org:443?cert=" + canary,
		"free text in an option set by its path": "vless://" + uuid + "@example.org:443?security=tls&sb.tls.min_version=" + canary + "%20%40x",
		"a flow of several lines":                "vless://" + uuid + "@example.org:443?security=tls&type=ws&sb.flow=AAA%0A" + canary,
		"a transport type of several lines":      "vless://" + uuid + "@example.org:443?security=tls&type=ws&sb.transport.type=x%0A" + canary + "&sb.transport.path=/p",
		// these two are refused by sing-box, which quotes what it was given
		"a transport type with a tab":      "vless://" + uuid + "@example.org:443?security=tls&type=ws&sb.transport.type=x%09" + canary,
		"a transport type with a new line": "vless://" + uuid + "@example.org:443?security=tls&type=ws&sb.transport.type=x%0A" + canary,
	} {
		var output, errorOutput bytes.Buffer
		status := decodeLink([]string{link}, strings.NewReader(""), &output, &errorOutput)
		require.Equal(t, decodeLinkExitBadLink, status, "%s: %s", name, errorOutput.String())
		require.Empty(t, output.String(), name)
		require.True(t, strings.HasPrefix(errorOutput.String(), "error: "), "%s: %s", name, errorOutput.String())
		require.Equal(t, 1, strings.Count(errorOutput.String(), "\n"), "%s: %s", name, errorOutput.String())
		require.NotContains(t, errorOutput.String(), canary, name)
		require.NotContains(t, errorOutput.String(), "goroutine", name)
	}
	// an outbound whose building fails outright is a link that cannot be used
	require.Equal(t, `invalid "..."`, plainMessage(`invalid "a\"b\\c1"`, []string{`a"b\c1`}))
	// what the link keeps secret is taken out as it stands in the message, then the
	// message is made one line
	require.Equal(t, "bad ... here", plainMessage("bad x\tSECRET here", []string{"x\tSECRET"}))
	require.Equal(t, "bad ... here", plainMessage("bad x\nSECRET here\nmore", []string{"x\nSECRET"}))
	require.Equal(t, "a b c", plainMessage("a\rb\tc", nil))
}

// A warning is one line too, whatever stands in the link in the place of a name.
func TestDecodeLinkWarningsAreLines(t *testing.T) {
	const canary = "CANARY0f6d2c"
	const uuid = "6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11"
	for name, link := range map[string]string{
		"a name of several lines": "vless://" + uuid + "@example.org:443?security=tls&x%0Aerror%3A%20" + canary + "=1",
		"another link for a name": "vless://" + uuid + "@example.org:443?security=tls&vless://" + canary + "@example.org:443?type=ws",
		"an unknown name":         "vless://" + uuid + "@example.org:443?security=tls&NoSuchName=" + canary,
	} {
		var output, errorOutput bytes.Buffer
		status := decodeLink([]string{link}, strings.NewReader(""), &output, &errorOutput)
		require.Equal(t, 0, status, "%s: %s", name, errorOutput.String())
		require.NotEmpty(t, output.String(), name)
		lines := strings.Split(strings.TrimSuffix(errorOutput.String(), "\n"), "\n")
		require.Len(t, lines, 1, "%s: %s", name, errorOutput.String())
		require.True(t, strings.HasPrefix(lines[0], "warning: "), "%s: %s", name, errorOutput.String())
		require.NotContains(t, errorOutput.String(), canary, name)
	}
	require.Equal(t, "a b c", oneLine("a\nb\tc"))
}

// An outbound that does not get built in time is a link that cannot be used.
func TestDecodeLinkBuildTimeout(t *testing.T) {
	timeout, build := decodeLinkBuildTimeout, buildDecoded
	t.Cleanup(func() { decodeLinkBuildTimeout, buildDecoded = timeout, build })
	decodeLinkBuildTimeout = 200 * time.Millisecond
	entered, release := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(release) })
	buildDecoded = func([]byte) ([]string, error) {
		close(entered)
		<-release
		return nil, nil
	}
	var output, errorOutput bytes.Buffer
	start := time.Now()
	status := decodeLink([]string{"vless://6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11@example.org:443"}, strings.NewReader(""), &output, &errorOutput)
	require.Equal(t, decodeLinkExitBadLink, status)
	require.Empty(t, output.String())
	require.Equal(t, "error: this sing-box takes too long to build the outbound of the link\n", errorOutput.String())
	require.Less(t, time.Since(start), 5*time.Second)
	// the build that was left behind has taken its function: the variable is free again
	<-entered
	// and one whose building fails outright
	buildDecoded = func([]byte) ([]string, error) {
		var short [8]byte
		index := 9
		return nil, E.New(short[index%len(short)+index])
	}
	errorOutput.Reset()
	status = decodeLink([]string{"vless://6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11@example.org:443"}, strings.NewReader(""), &output, &errorOutput)
	require.Equal(t, decodeLinkExitBadLink, status)
	require.Equal(t, "error: this sing-box cannot build the outbound of the link\n", errorOutput.String())
}

// Scripts read the features as whole names between commas, and ask for the ones they
// depend on by name: the names of the releases before stay, in their order.
func TestVersionFeatures(t *testing.T) {
	seen := make(map[string]bool)
	for _, feature := range versionFeatures {
		require.NotContains(t, feature, ",")
		require.NotContains(t, feature, " ")
		require.False(t, seen[feature], feature)
		seen[feature] = true
	}
	require.Equal(t, []string{"urltest.fallbacks", "urltest.download_url", "transport.xhttp", "tools.decode-link"}, versionFeatures[:4])
	require.True(t, seen["tls.utls-fallback"])
}

// outboundAvailable reports whether this sing-box was built with the outbound type: one
// left out of the build is there as a stub that refuses to be made, with these words.
func outboundAvailable(outboundType string) bool {
	_, err := checkDecoded([]byte(`{"type":"` + outboundType + `","tag":"probe"}`))
	return err == nil || !(strings.Contains(err.Error(), "is not included in this build") || strings.Contains(err.Error(), "unknown outbound type"))
}

// One link of every scheme: the command prints an outbound exactly when this build has
// the type of the outbound, and names the build otherwise. What is printed has been
// built, so "sing-box check" takes it.
func TestDecodeLinkEveryScheme(t *testing.T) {
	const uuid = "6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11"
	links := map[string]string{
		"vless":       "vless://" + uuid + "@example.org:443?security=reality&pbk=YBZ6SAP7KfiD5YJiyAGvD49eNYW-f-7IlhMarfyy4k0&sid=0123456789abcdef&flow=xtls-rprx-vision&sni=www.example.com",
		"trojan":      "trojan://password@example.org:443?type=ws&path=%2Fws&sni=example.org",
		"ss":          "ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206ZG1DbHkvWmgxNVd3OStzK0dGWGlGVElrcHc3Yy9xQ0lTYUJyYWk3V2hoWT0@127.0.0.1:25144",
		"socks":       "socks://dXNlcjpwYXNz@127.0.0.1:1080",
		"socks4":      "socks4://127.0.0.1:1080",
		"socks4a":     "socks4a://127.0.0.1:1080",
		"socks5":      "socks5://user:pass@127.0.0.1:1080",
		"socks5h":     "socks5h://127.0.0.1:1080",
		"hysteria2":   "hysteria2://password@example.org:443,5000-6000/?sni=example.org&obfs=salamander&obfs-password=x&insecure=1",
		"hy2":         "hy2://password@example.org",
		"tuic":        "tuic://" + uuid + ":password@example.org:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3",
		"vmess":       "vmess://" + uuid + "@example.org:443?type=ws&security=tls&path=%2Fws",
		"http":        "http://user:pass@example.org:3128",
		"https":       "https://user:pass@example.org:8443",
		"hysteria":    "hysteria://example.org:36712?auth=secret&upmbps=10&downmbps=50&peer=example.org",
		"anytls":      "anytls://password@example.org:8443?sni=example.org",
		"naive+https": "naive+https://user:pass@example.org",
		"naive+quic":  "naive+quic://user:pass@example.org",
	}
	require.False(t, outboundAvailable("no-such-type-is-a-stub"), "an unknown type is not a type of the build")
	for scheme, outboundType := range sharelink.Schemes() {
		link, hasLink := links[scheme]
		require.True(t, hasLink, "no test link of the scheme %s", scheme)
		var output, errorOutput bytes.Buffer
		status := decodeLink([]string{link}, strings.NewReader(""), &output, &errorOutput)
		if outboundAvailable(outboundType) {
			require.Zero(t, status, "%s: %s", scheme, errorOutput.String())
			var outbound map[string]any
			require.NoError(t, json.Unmarshal(output.Bytes(), &outbound), scheme)
			require.Equal(t, outboundType, outbound["type"], scheme)
			_, err := checkDecoded(output.Bytes())
			require.NoError(t, err, scheme)
		} else {
			require.Equal(t, decodeLinkExitBadLink, status, scheme)
			require.Empty(t, output.String(), scheme)
			require.Contains(t, errorOutput.String(), "error: "+outboundType+" outbound is not included in this build", scheme)
		}
		require.NotContains(t, errorOutput.String(), uuid, scheme)
	}
}

// An option named by its path goes through the same building: what the outbound takes is
// printed, what it refuses is the error of the command.
func TestDecodeLinkOptionPaths(t *testing.T) {
	const link = "vless://6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11@example.org:443?security=tls&sni=example.org&type=ws"
	run := func(parameters string) (int, string, string) {
		var output, errorOutput bytes.Buffer
		status := decodeLink([]string{link + parameters}, strings.NewReader(""), &output, &errorOutput)
		return status, output.String(), errorOutput.String()
	}
	status, output, errorOutput := run("&sb.multiplex.enabled=1&sb.multiplex.protocol=h2mux&sb.tls.fragment=1&sb.tls.spoof=packagist.org&sb.tls.spoof_method=wrong-md5")
	require.Zero(t, status, errorOutput)
	require.Empty(t, errorOutput)
	var outbound struct {
		TLS struct {
			Fragment bool   `json:"fragment"`
			Spoof    string `json:"spoof"`
		} `json:"tls"`
		Multiplex struct {
			Protocol string `json:"protocol"`
		} `json:"multiplex"`
	}
	require.NoError(t, json.Unmarshal([]byte(output), &outbound))
	require.True(t, outbound.TLS.Fragment)
	require.Equal(t, "packagist.org", outbound.TLS.Spoof)
	require.Equal(t, "h2mux", outbound.Multiplex.Protocol)
	for parameters, say := range map[string]string{
		"&sb.tls.min_version=9.9":                                   "error: ",
		"&sb.tls.spoof=example.org":                                 "error: `spoof` must differ from `server_name`",
		"&sb.multiplex.enabled=1&sb.multiplex.protocol=carrier":     "error: ",
		"&sb.detour=direct":                                         "error: the option detour is not for a link to set (another object)",
		"&sb.tls.certificate_path=%2Fetc":                           "error: the option tls.certificate_path is not for a link to set (a local file)",
		"&sb.no_such=1":                                             "error: this sing-box has no option no_such",
		"&sb.multiplex.enabled=1&sb.multiplex.max_connections=many": "error: the value of the link parameter sb.multiplex.max_connections does not fit the option",
	} {
		status, output, errorOutput := run(parameters)
		require.Equal(t, decodeLinkExitBadLink, status, parameters)
		require.Empty(t, output, parameters)
		require.True(t, strings.HasPrefix(errorOutput, say), "%s: %q", parameters, errorOutput)
	}
}

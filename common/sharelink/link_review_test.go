package sharelink

import (
	"context"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

// optionsOf reads the options of a decoded outbound into the structure of its type, as
// the configuration reader would.
func optionsOf[T any](t *testing.T, outbound *Outbound) T {
	t.Helper()
	content, err := json.Marshal(outbound.options)
	require.NoError(t, err)
	var options T
	require.NoError(t, json.UnmarshalContext(context.Background(), content, &options))
	return options
}

func tlsOf(t *testing.T, link string) *option.OutboundTLSOptions {
	t.Helper()
	outbound, _, err := Decode(link)
	require.NoError(t, err)
	return optionsOf[option.OutboundTLSOptionsContainer](t, outbound).TLS
}

// Fingerprints as Xray reads them: any case, Chrome's by default, "unsafe" for
// none, and nothing sing-box would refuse later.
func TestFingerprints(t *testing.T) {
	t.Parallel()
	base := "vless://" + testUUID + "@example.org:443?security=tls"
	require.Equal(t, "chrome", tlsOf(t, base).UTLS.Fingerprint)
	require.Equal(t, "firefox", tlsOf(t, base+"&fp=Firefox").UTLS.Fingerprint)
	require.Nil(t, tlsOf(t, base+"&fp=unsafe").UTLS)
	require.Equal(t, "chrome", tlsOf(t, "trojan://p@example.org:443").UTLS.Fingerprint)
	require.Equal(t, "chrome", tlsOf(t, "vless://"+testUUID+"@example.org:443?security=REALITY&pbk=K").UTLS.Fingerprint)
	// a name only Xray knows gives the fingerprint of the same browser, with a warning
	for link, fingerprint := range map[string]string{
		base + "&fp=hellochrome_131":  "chrome",
		base + "&fp=HelloFirefox_148": "firefox",
		base + "&fp=randomizednoalpn": "randomized",
		"vless://" + testUUID + "@h:1?security=reality&pbk=K&fp=hellosafari_26_3": "safari",
	} {
		outbound, warnings, err := Decode(link)
		require.NoError(t, err, link)
		require.Equal(t, fingerprint, optionsOf[option.OutboundTLSOptionsContainer](t, outbound).TLS.UTLS.Fingerprint, link)
		require.Len(t, warnings, 1, link)
		require.Contains(t, warnings[0], "has no counterpart, "+fingerprint+" is used", link)
	}
	options, warnings := transportOf(t, xhttpLink(`{"downloadSettings":{"address":"a","port":1,"security":"tls","tlsSettings":{"fingerprint":"hellochrome_131"}}}`, url.QueryEscape, ""))
	require.Equal(t, "chrome", options.Download.TLS.UTLS.Fingerprint)
	require.Len(t, warnings, 1)
	// a name nobody knows: no imitation with TLS, as in Xray; REALITY cannot do without
	outbound, warnings, err := Decode(base + "&fp=netscape")
	require.NoError(t, err)
	require.Nil(t, optionsOf[option.OutboundTLSOptionsContainer](t, outbound).TLS.UTLS)
	require.Len(t, warnings, 1)
	for _, link := range []string{
		"vless://" + testUUID + "@example.org:443?security=reality&pbk=K&fp=unsafe",
		"vless://" + testUUID + "@example.org:443?security=reality&pbk=K&fp=netscape",
	} {
		_, _, err := Decode(link)
		require.ErrorContains(t, err, "unsupported fingerprint", link)
	}
	options, _ = transportOf(t, xhttpLink(`{"downloadSettings":{"address":"[2001:db8::1]","port":1,"network":"XHTTP","security":"TLS","tlsSettings":{"fingerprint":"Edge"},"xhttpSettings":null,"splithttpSettings":{"path":"/s"}}}`, url.QueryEscape, ""))
	require.Equal(t, "edge", options.Download.TLS.UTLS.Fingerprint)
	require.Equal(t, "2001:db8::1", options.Download.Server)
	require.Equal(t, "/s", options.Download.Path)
}

func TestFlows(t *testing.T) {
	t.Parallel()
	base := "vless://" + testUUID + "@example.org:443?security=reality&pbk=K&flow="
	outbound, _, err := Decode(base + "xtls-rprx-vision-udp443")
	require.NoError(t, err)
	require.Equal(t, "xtls-rprx-vision", optionsOf[option.VLESSOutboundOptions](t, outbound).Flow)
	for _, flow := range []string{"xtls-rprx-direct", "none", "xtls-rprx-origin"} {
		_, _, err = Decode(base + flow)
		require.ErrorContains(t, err, "unsupported flow", flow)
	}
	_, _, err = Decode(base + "xtls-rprx-vision&type=xhttp")
	require.ErrorContains(t, err, "not supported over the xhttp transport")
	_, warnings, err := Decode("trojan://p@example.org:443?flow=xtls-rprx-vision")
	require.NoError(t, err)
	require.Len(t, warnings, 1)
}

// What must be refused, and without repeating the link: an error message ends
// up in a log.
func TestRefusedWithoutEcho(t *testing.T) {
	t.Parallel()
	const secret = "5ec2e7aa-0000-4000-8000-5ec2e7000000"
	for name, link := range map[string]string{
		"two links on a line":  "vless://" + testUUID + "@h:1 vless://" + secret + "@h:2",
		"a link in a value":    "vless://" + testUUID + "@h:1?type=tcp vless://" + secret + "@h:2?type=ws",
		"a link after a mode":  "vless://" + testUUID + "@h:1?type=xhttp&mode=packet-up vless://" + secret + "@h:2?type=xhttp",
		"no scheme":            secret + "@example.org:443?type=ws&path=x://y",
		"bare ipv6":            "vless://" + secret + "@2001:db8::1:443",
		"security with a tail": "vless://" + secret + "@h:1?security=tls1sni=" + secret + ".example.org",
		"header type":          "vless://" + testUUID + "@h:1?type=tcp&headerType=none@" + secret,
		"not a uuid":           "vless://" + secret + "-and-more-of-it@h:1",
		"grpc custom path":     "vless://" + testUUID + "@h:1?type=grpc&serviceName=%2Fa%2Fb",
		"stream-one download":  "vless://" + testUUID + "@h:1?type=xhttp&mode=stream-one&extra=" + url.QueryEscape(`{"downloadSettings":{"address":"a","port":1}}`),
	} {
		outbound, _, err := Decode(link)
		require.Error(t, err, name)
		require.Nil(t, outbound, name)
		require.NotContains(t, strings.ToLower(err.Error()), secret[:13], name)
		require.NotContains(t, err.Error(), "://", name)
	}
	// what could not be read is not repeated, and no type of the program is named
	for name, test := range map[string]struct{ link, say string }{
		"extra that is not an object": {xhttpLink(`"text"`, url.QueryEscape, ""), "read extra: not a JSON object"},
		"a range in extra":            {xhttpLink(`{"xPaddingBytes":"a-`+secret+`"}`, url.QueryEscape, ""), "invalid range"},
		"a range in a parameter":      {xhttpLink(`{}`, url.QueryEscape, "&x_padding_bytes=a-"+secret), "invalid range in the link parameter x_padding_bytes"},
	} {
		_, _, err := Decode(test.link)
		require.ErrorContains(t, err, test.say, name)
		require.NotContains(t, err.Error(), secret[:13], name)
		require.NotContains(t, err.Error(), "sharelink", name)
	}
	// a short user is Xray's "string turned into a UUID"
	_, _, err := Decode("vless://my-user@h:1")
	require.NoError(t, err)
	// a plain word is shown
	_, _, err = Decode("vless://" + testUUID + "@h:1?type=tor")
	require.ErrorContains(t, err, "unsupported transport: tor")
	// a byte order mark before the link
	_, _, err = Decode("\ufeffvless://" + testUUID + "@h:1")
	require.NoError(t, err)
}

func TestExtraSettlesWhatItNames(t *testing.T) {
	t.Parallel()
	base := "vless://" + testUUID + "@example.org:443?type=xhttp&"
	options, _ := transportOf(t, base+"noGRPCHeader=true&sessionIDPlacement=query&xPaddingBytes=5-9&x_padding_bytes=7-8&uplinkHTTPMethod=PUT&extra="+
		url.QueryEscape(`{"noGRPCHeader":false,"sessionPlacement":"header","xPaddingBytes":0}`))
	require.False(t, options.NoGRPCHeader, "false in extra is a setting")
	require.Equal(t, "header", options.SessionPlacement, "the older name in extra settles the newer one of the link")
	require.Nil(t, options.XPaddingBytes)
	require.Equal(t, "PUT", options.UplinkHTTPMethod, "what extra does not name comes from the link")

	// several spellings of Host: the same answer every time
	link := base + "extra=" + url.QueryEscape(`{"headers":{"host":"b","Host":"a","HOST":"c","X":"y"}}`)
	for i := 0; i < 20; i++ {
		options, warnings := transportOf(t, link)
		require.Equal(t, "c", options.Host)
		require.Len(t, warnings, 2)
		require.Len(t, options.Headers, 1)
	}

	// the download leg sends GETs only
	options, _ = transportOf(t, base+"mode=packet-up&extra="+url.QueryEscape(
		`{"downloadSettings":{"address":"d","port":1,"xhttpSettings":{"uplinkHTTPMethod":"GET","uplinkDataPlacement":"header","mode":"stream-one","path":"/d"}}}`))
	content, err := json.Marshal(options.Download)
	require.NoError(t, err)
	require.JSONEq(t, `{"server":"d","server_port":1,"path":"/d"}`, string(content))
}

func TestSmallLeniencies(t *testing.T) {
	t.Parallel()
	// early data that is not a number is none, as with Xray
	content, _ := decodeJSON(t, "vless://"+testUUID+"@example.org:80?type=ws&path=%2Fws%3Fed%3Dabc&security=none")
	require.JSONEq(t, `{"type":"vless","server":"example.org","server_port":80,"uuid":"`+testUUID+`","transport":{"type":"ws","path":"/ws"}}`, content)
	// REALITY over a transport Xray does not serve it on
	_, warnings := decodeJSON(t, "vless://"+testUUID+"@example.org:443?type=ws&security=reality&pbk=K")
	require.Equal(t, []string{"Xray does not serve REALITY over this transport"}, warnings)
	// the names of parameters as the link writes them, a wrong type named plainly
	_, warnings = decodeJSON(t, "vless://"+testUUID+"@example.org:443?type=xhttp&security=none&xPaddingBytesTo=5&=x")
	require.Equal(t, []string{"xPaddingBytesTo is not supported and is ignored"}, warnings)
	_, _, err := Decode(xhttpLink(`{"scMaxBufferedPosts":"many"}`, url.QueryEscape, ""))
	require.ErrorContains(t, err, "scMaxBufferedPosts has a value of the wrong type")
	require.NotContains(t, err.Error(), "xraySplitHTTP")
}

// A transport that speaks one protocol keeps the ALPN to itself, as with Xray: the list a
// panel writes for every host does not reach it.
func TestTransportALPN(t *testing.T) {
	t.Parallel()
	base := "vless://" + testUUID + "@example.org:443?security=tls&sni=example.org&alpn=h2%2Chttp%2F1.1"
	for transport, want := range map[string][]string{
		"&type=tcp":                               {"h2", "http/1.1"},
		"":                                        {"h2", "http/1.1"},
		"&type=ws&path=%2Fws":                     nil,
		"&type=httpupgrade&path=%2Fhu":            nil,
		"&type=grpc&serviceName=svc":              nil,
		"&type=http&path=%2Fh":                    nil,
		"&type=xhttp&path=%2Fx":                   {"h2", "http/1.1"},
		"&type=ws&path=%2Fws&sb.tls.alpn=h2":      {"h2"},
		"&type=grpc&serviceName=s&sb.tls.alpn=h2": {"h2"},
	} {
		require.Equal(t, want, []string(tlsOf(t, base+transport).ALPN), transport)
	}
	// with VMess and Trojan links too
	require.Empty(t, tlsOf(t, "trojan://p@example.org:443?type=ws&alpn=h2%2Chttp%2F1.1").ALPN)
	require.Empty(t, tlsOf(t, "vmess://"+b64(`{"v":"2","add":"example.org","port":443,"id":"`+testUUID+`","net":"ws","tls":"tls","alpn":"h2,http/1.1"}`)).ALPN)
	require.Equal(t, []string{"h2", "http/1.1"}, []string(tlsOf(t, "vmess://"+b64(`{"v":"2","add":"example.org","port":443,"id":"`+testUUID+`","net":"tcp","tls":"tls","alpn":"h2,http/1.1"}`)).ALPN))
}

// The name of a gRPC service as Marzban writes that of a custom path.
func TestGRPCServiceNameEscapedTwice(t *testing.T) {
	t.Parallel()
	base := "vless://" + testUUID + "@example.org:443?security=none&type=grpc&serviceName="
	for given, want := range map[string]string{
		"svc":              "svc",
		"%252Fsvc%252FTun": "svc",
		"my%2520svc":       "my%20svc",
		"a%2Eb":            "a.b",
		"%E2%9C%93":        "\u2713",
		"%25E2%259C%2593":  "%E2%9C%93",
	} {
		content, _ := decodeJSON(t, base+given)
		require.JSONEq(t, `{"type":"vless","server":"example.org","server_port":443,"uuid":"`+testUUID+`","transport":{"type":"grpc","service_name":"`+want+`"}}`, content, given)
	}
}

// What sing-box would quote in its error when it refuses an outbound is checked by the
// decoder first, with a text of its own: a user of the wrong shape may be a password.
func TestRefusedBeforeSingBoxQuotes(t *testing.T) {
	t.Parallel()
	const canary = "CANARY0f6d2c"
	for link, want := range map[string]string{
		"tuic://" + canary + ":pass@example.org:443":                                             "the user of the link is not a UUID and a password",
		"tuic://6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c1:" + canary + "@example.org:443":              "the user of the link is not a UUID and a password",
		"ss://" + b64(canary+" x:pass") + "@example.org:443":                                     "the user of the link is not a method and a password",
		"ss://" + canary + "%40x:pass@example.org:443":                                           "the user of the link is not a method and a password",
		"hysteria2://pass@example.org:443?obfs=" + canary + "%20x&obfs-password=y":               "unsupported obfuscation of Hysteria 2",
		"vless://" + testUUID + "@example.org:443?security=reality&pbk=K&sid=0123456789abcdef01": "the REALITY short id (sid)",
		"vless://" + testUUID + "@example.org:443?security=reality&pbk=K&sid=abc":                "the REALITY short id (sid)",
		"vless://" + testUUID + "@example.org:443?security=reality&pbk=K&sid=" + canary:          "the REALITY short id (sid)",
	} {
		outbound, _, err := Decode(link)
		require.Nil(t, outbound, link)
		require.ErrorContains(t, err, want, link)
		require.NotContains(t, err.Error(), canary, link)
	}
	// and what is of the right shape passes
	for _, link := range []string{
		"tuic://" + testUUID + ":pass@example.org:443?alpn=h3",
		"tuic://" + strings.ReplaceAll(testUUID, "-", "") + ":pass@example.org:443?alpn=h3",
		"ss://" + b64("2022-blake3-chacha20-poly1305:"+canary) + "@example.org:443",
		"vless://" + testUUID + "@example.org:443?security=reality&pbk=K&sid=",
		"vless://" + testUUID + "@example.org:443?security=reality&pbk=K&sid=0123456789ABCDEF",
	} {
		_, warnings, err := Decode(link)
		require.NoError(t, err, link)
		require.Empty(t, warnings, link)
	}
	// a TUIC link without an ALPN is taken, with a word about it
	_, warnings, err := Decode("tuic://" + testUUID + ":pass@example.org:443")
	require.NoError(t, err)
	require.Len(t, warnings, 1)
	require.Contains(t, warnings[0], "names no ALPN")
}

// A Shadowsocks plugin has options of its own in one string, and v2ray-plugin reads the
// file one of them names: not for a link to set, however the name is written.
func TestPluginOptionThatIsAFile(t *testing.T) {
	t.Parallel()
	base := "ss://" + b64("aes-128-gcm:password") + "@example.org:443?"
	for _, parameters := range []string{
		"plugin=" + url.QueryEscape("v2ray-plugin;tls;cert=/etc/passwd"),
		"plugin=" + url.QueryEscape("v2ray-plugin;cert=/dev/zero;tls"),
		"plugin=" + url.QueryEscape(`v2ray-plugin;tls;c\ert=/dev/zero`),
		"plugin=" + url.QueryEscape("v2ray-plugin;tls;cert"),
		"sb.plugin=v2ray-plugin&sb.plugin_opts=" + url.QueryEscape("tls;cert=/dev/zero"),
		"plugin=v2ray-plugin&sb.plugin_opts=" + url.QueryEscape("cert=/dev/zero"),
	} {
		require.Equal(t, "sb-denied", refusalID(t, base+parameters), parameters)
	}
	for _, parameters := range []string{
		"plugin=" + url.QueryEscape("v2ray-plugin;tls;host=cdn.example.org;path=/ws;mux=0"),
		"plugin=" + url.QueryEscape("v2ray-plugin;tls;certRaw=MIIB;host=cdn.example.org"),
		"plugin=" + url.QueryEscape("obfs-local;obfs=http;obfs-host=cdn.example.org"),
		"plugin=" + url.QueryEscape("simple-obfs;obfs=tls"),
	} {
		_, _, err := Decode(base + parameters)
		require.NoError(t, err, parameters)
	}
	_, _, err := Decode(base + "plugin=" + url.QueryEscape("a plugin;x"))
	require.ErrorContains(t, err, "the plugin of the link is not a name")

	// every option the plugins of sing-box read is known here: a new one is looked at
	// before a link may set it
	pattern := regexp.MustCompile(`pluginOpts\.Get\("([^"]+)"\)`)
	entries, err := os.ReadDir("../../transport/sip003")
	require.NoError(t, err)
	read := make(map[string]bool)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		content, err := os.ReadFile("../../transport/sip003/" + entry.Name())
		require.NoError(t, err)
		for _, match := range pattern.FindAllSubmatch(content, -1) {
			read[string(match[1])] = true
		}
	}
	require.NotEmpty(t, read)
	for name := range read {
		require.Contains(t, pluginOptions, name, "a plugin option of sing-box nobody has looked at")
	}
}

// The ports a Hysteria link hops over are bounded: sing-box writes them out one by one.
func TestPortListBound(t *testing.T) {
	t.Parallel()
	whole := strings.TrimSuffix(strings.Repeat("1-65535,", 2), ",")
	for _, link := range []string{
		"hysteria2://password@example.org:443?mport=" + whole,
		"hysteria2://password@example.org:" + whole,
		"hysteria2://password@example.org:443?sb.server_ports=" + url.QueryEscape("1:65535,1:65535"),
		"hysteria2://password@example.org:443?sb.server_ports=" + url.QueryEscape(`["1:65535","2:2"]`),
	} {
		require.Equal(t, "ports", refusalID(t, link), link)
	}
	content, _ := decodeJSON(t, "hysteria2://password@example.org:443?mport=443,20000-50000")
	require.Contains(t, content, `"server_ports":["443:443","20000:50000"]`)
	_, _, err := Decode("hysteria2://password@example.org:443?sb.server_ports=" + url.QueryEscape("6000:5000"))
	require.ErrorContains(t, err, "invalid port in the list of ports")
}

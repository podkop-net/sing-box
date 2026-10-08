package sharelink

import (
	"net/url"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

const testUUID = "6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11"

func decodeJSON(t *testing.T, link string) (string, []string) {
	t.Helper()
	outbound, warnings, err := Decode(link)
	require.NoError(t, err)
	content, err := json.Marshal(outbound)
	require.NoError(t, err)
	return string(content), warnings
}

// uriComponent encodes as JavaScript's encodeURIComponent does: no "+".
func uriComponent(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func xhttpLink(extra string, encode func(string) string, more string) string {
	return "vless://" + testUUID + "@example.org:443?type=xhttp&security=tls&sni=example.org&fp=chrome&alpn=h2%2Chttp%2F1.1" +
		"&path=%2Fapi%2F&host=cdn.example.org&mode=auto" + more + "&extra=" + encode(extra) + "#name"
}

func TestVLESSXHTTP(t *testing.T) {
	t.Parallel()
	extra := `{"xPaddingBytes":"100-1000","scMaxEachPostBytes":1000000,"scMinPostsIntervalMs":"30","noGRPCHeader":true,` +
		`"headers":{"X-Test":"a b"},"xmux":{"maxConcurrency":"16-32","hMaxRequestTimes":"600-900","hMaxReusableSecs":"1800-3000","hKeepAlivePeriod":0},` +
		`"scMaxBufferedPosts":30,"noSSEHeader":false,"mode":"packet-up","host":"other","path":"/other"}`
	content, warnings := decodeJSON(t, xhttpLink(extra, url.QueryEscape, ""))
	require.Empty(t, warnings)
	require.JSONEq(t, `{
		"type": "vless", "tag": "name", "server": "example.org", "server_port": 443, "uuid": "`+testUUID+`",
		"tls": {"enabled": true, "server_name": "example.org", "alpn": ["h2", "http/1.1"], "utls": {"enabled": true, "fingerprint": "chrome"}},
		"transport": {
			"type": "xhttp", "mode": "auto", "host": "cdn.example.org", "path": "/api/",
			"headers": {"X-Test": "a b"},
			"x_padding_bytes": "100-1000", "sc_max_each_post_bytes": "1000000", "sc_min_posts_interval_ms": "30",
			"no_grpc_header": true, "sc_max_buffered_posts": 30,
			"xmux": {"max_concurrency": "16-32", "h_max_request_times": "600-900", "h_max_reusable_secs": "1800-3000"}
		}
	}`, content)
}

// Every way the generators encode "extra" gives the same outbound.
func TestExtraEncodings(t *testing.T) {
	t.Parallel()
	compact := `{"xPaddingBytes":"100-1000","headers":{"User-Agent":"Mozilla/5.0 (X11; Linux) a+b"}}`
	spaced := `{"xPaddingBytes": "100-1000", "headers": {"User-Agent": "Mozilla/5.0 (X11; Linux) a+b"}}`
	want, _ := decodeJSON(t, xhttpLink(compact, url.QueryEscape, ""))
	require.Contains(t, want, `Mozilla/5.0 (X11; Linux) a+b`)
	for name, link := range map[string]string{
		"encodeURIComponent": xhttpLink(compact, uriComponent, ""),
		// Marzban: json.dumps with spaces, form encoding
		"spaces as plus":  xhttpLink(spaced, url.QueryEscape, ""),
		"spaces as %20":   xhttpLink(spaced, uriComponent, ""),
		"slash unescaped": xhttpLink(compact, func(s string) string { return strings.ReplaceAll(uriComponent(s), "%2F", "/") }, ""),
	} {
		content, warnings := decodeJSON(t, link)
		require.Empty(t, warnings, name)
		require.JSONEq(t, want, content, name)
	}
}

func transportOf(t *testing.T, link string) (option.V2RayXHTTPOptions, []string) {
	t.Helper()
	outbound, warnings, err := Decode(link)
	require.NoError(t, err)
	transport := optionsOf[option.VLESSOutboundOptions](t, outbound).Transport
	require.NotNil(t, transport)
	require.Equal(t, "xhttp", transport.Type)
	return transport.XHTTPOptions, warnings
}

func TestXHTTPDetails(t *testing.T) {
	t.Parallel()
	t.Run("legacy session names", func(t *testing.T) {
		options, warnings := transportOf(t, xhttpLink(`{"sessionPlacement":"header","sessionKey":"X-S"}`, url.QueryEscape, ""))
		require.Empty(t, warnings)
		require.Equal(t, "header", options.SessionPlacement)
		require.Equal(t, "X-S", options.SessionKey)
	})
	t.Run("new session names win", func(t *testing.T) {
		options, _ := transportOf(t, xhttpLink(`{"sessionPlacement":"header","sessionIDPlacement":"query","sessionIDKey":"s","sessionKey":"X-S"}`, url.QueryEscape, ""))
		require.Equal(t, "query", options.SessionPlacement)
		require.Equal(t, "s", options.SessionKey)
	})
	t.Run("flat padding of 3x-ui", func(t *testing.T) {
		options, _ := transportOf(t, xhttpLink(`{}`, url.QueryEscape, "&x_padding_bytes=200-300"))
		require.Equal(t, &option.V2RayXHTTPRange{From: 200, To: 300}, options.XPaddingBytes)
		options, _ = transportOf(t, xhttpLink(`{"xPaddingBytes":"5-6"}`, url.QueryEscape, "&x_padding_bytes=200-300"))
		require.Equal(t, &option.V2RayXHTTPRange{From: 5, To: 6}, options.XPaddingBytes)
	})
	t.Run("zero is the default", func(t *testing.T) {
		options, _ := transportOf(t, xhttpLink(`{"xPaddingBytes":0,"scMaxEachPostBytes":"","xmux":{"maxConcurrency":0},"uplinkChunkSize":null}`, url.QueryEscape, ""))
		require.Nil(t, options.XPaddingBytes)
		require.Nil(t, options.ScMaxEachPostBytes)
		require.Nil(t, options.UplinkChunkSize)
		require.Nil(t, options.Xmux)
	})
	t.Run("unknown and obsolete keys", func(t *testing.T) {
		options, warnings := transportOf(t, xhttpLink(`{"scMaxConcurrentPosts":100,"keepAlivePeriod":30,"future":1,"another":{}}`, url.QueryEscape, ""))
		require.Equal(t, []string{"extra: another is not supported and is ignored", "extra: future is not supported and is ignored"}, warnings)
		require.Equal(t, "/api/", options.Path)
	})
	t.Run("host among the headers", func(t *testing.T) {
		link := "vless://" + testUUID + "@example.org:443?type=xhttp&extra=" + url.QueryEscape(`{"headers":{"host":"h.example.org","A":"b"}}`)
		options, warnings := transportOf(t, link)
		require.Empty(t, warnings)
		require.Equal(t, "h.example.org", options.Host)
		require.Len(t, options.Headers, 1)
	})
	t.Run("no extra, splithttp", func(t *testing.T) {
		options, warnings := transportOf(t, "vless://"+testUUID+"@[2001:db8::1]:8443?type=splithttp&path=%2Fp&mode=packet-up")
		require.Empty(t, warnings)
		require.Equal(t, option.V2RayXHTTPOptions{Mode: "packet-up", V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{Path: "/p"}}, options)
	})
}

func TestXHTTPDownload(t *testing.T) {
	t.Parallel()
	// the shape Hiddify writes
	extra := `{"downloadSettings":{"address":"down.example.org","port":8443,"network":"xhttp","security":"tls",` +
		`"tlsSettings":{"serverName":"down.example.org","alpn":["h2"],"fingerprint":"firefox"},` +
		`"xhttpSettings":{"path":"/d","host":"down.example.org","mode":"auto","headers":{"User-Agent":"x"}},` +
		`"sockopt":{"dialerProxy":"p"}},"headers":{"User-Agent":"x"}}`
	options, warnings := transportOf(t, xhttpLink(extra, url.QueryEscape, ""))
	require.Equal(t, []string{"downloadSettings: sockopt is not supported and is ignored"}, warnings)
	content, err := json.Marshal(options.Download)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"server": "down.example.org", "server_port": 8443, "host": "down.example.org", "path": "/d", "headers": {"User-Agent": "x"},
		"tls": {"enabled": true, "server_name": "down.example.org", "alpn": "h2", "utls": {"enabled": true, "fingerprint": "firefox"}}
	}`, string(content))

	extra = `{"downloadSettings":{"address":"192.0.2.1","port":443,"security":"reality",` +
		`"realitySettings":{"serverName":"www.example.com","password":"KEY","shortId":"0123","spiderX":"/"},` +
		`"xhttpSettings":{"path":"/d","xPaddingBytes":"1-2","extra":{"xPaddingBytes":"7-8","path":"/ignored","xmux":{"maxConnections":2}}}}}`
	options, warnings = transportOf(t, xhttpLink(extra, url.QueryEscape, ""))
	require.Empty(t, warnings)
	content, err = json.Marshal(options.Download)
	require.NoError(t, err)
	require.JSONEq(t, `{
		"server": "192.0.2.1", "server_port": 443, "path": "/d", "x_padding_bytes": "7-8", "xmux": {"max_connections": "2"},
		"tls": {"enabled": true, "server_name": "www.example.com", "utls": {"enabled": true, "fingerprint": "chrome"},
			"reality": {"enabled": true, "public_key": "KEY", "short_id": "0123"}}
	}`, string(content))

	for name, extra := range map[string]string{
		"no address":  `{"downloadSettings":{"port":443}}`,
		"no port":     `{"downloadSettings":{"address":"a"}}`,
		"network":     `{"downloadSettings":{"address":"a","port":1,"network":"ws"}}`,
		"security":    `{"downloadSettings":{"address":"a","port":1,"security":"xtls"}}`,
		"no key":      `{"downloadSettings":{"address":"a","port":1,"security":"reality"}}`,
		"not object":  `{"downloadSettings":"x"}`,
		"bad nesting": `{"downloadSettings":{"address":"a","port":1,"xhttpSettings":[1]}}`,
	} {
		_, _, err = Decode(xhttpLink(extra, url.QueryEscape, ""))
		require.Error(t, err, name)
	}
}

func TestOtherTransports(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct{ link, want string }{
		"reality vision": {
			"vless://" + testUUID + "@192.0.2.1:443?security=reality&sni=www.example.com&pbk=KEY&sid=0123&spx=%2F&flow=xtls-rprx-vision&type=tcp&encryption=none#%D0%B8%D0%BC%D1%8F%20100%",
			`{"type":"vless","tag":"%D0%B8%D0%BC%D1%8F%20100%","server":"192.0.2.1","server_port":443,"uuid":"` + testUUID + `","flow":"xtls-rprx-vision",
			"tls":{"enabled":true,"server_name":"www.example.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"KEY","short_id":"0123"}}}`,
		},
		"name": {
			"vless://" + testUUID + "@192.0.2.1:443?security=none#%D0%B8%D0%BC%D1%8F%201",
			`{"type":"vless","tag":"имя 1","server":"192.0.2.1","server_port":443,"uuid":"` + testUUID + `"}`,
		},
		"ws early data in the path": {
			"vless://" + testUUID + "@example.org:443/?security=tls&type=ws&host=h.example.org&path=%2Fws%3Fa%3D1%26ed%3D2560&allowInsecure=1&packetEncoding=xudp",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","packet_encoding":"xudp","tls":{"enabled":true,"insecure":true,"utls":{"enabled":true,"fingerprint":"chrome"}},
			"transport":{"type":"ws","path":"/ws?a=1","headers":{"Host":"h.example.org"},"max_early_data":2560,"early_data_header_name":"Sec-WebSocket-Protocol"}}`,
		},
		"grpc": {
			"vless://" + testUUID + "@example.org:443?security=tls&type=grpc&serviceName=svc&mode=gun",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"}},"transport":{"type":"grpc","service_name":"svc"}}`,
		},
		"httpupgrade": {
			"vless://" + testUUID + "@example.org:80?type=httpupgrade&host=h&path=%2Fu",
			`{"type":"vless","server":"example.org","server_port":80,"uuid":"` + testUUID + `","transport":{"type":"httpupgrade","host":"h","path":"/u"}}`,
		},
		"trojan": {
			"trojan://pass%3Aw%40rd@example.org:443?sni=s.example.org&type=http&host=a,b&path=%2Fh",
			`{"type":"trojan","server":"example.org","server_port":443,"password":"pass:w@rd","tls":{"enabled":true,"server_name":"s.example.org","utls":{"enabled":true,"fingerprint":"chrome"}},
			"transport":{"type":"http","host":["a","b"],"path":"/h"}}`,
		},
	} {
		content, warnings := decodeJSON(t, test.link)
		require.Empty(t, warnings, name)
		require.JSONEq(t, test.want, content, name)
	}
}

func TestWarnings(t *testing.T) {
	t.Parallel()
	_, warnings := decodeJSON(t, "vless://"+testUUID+"@example.org:443?security=reality&pbk=K&pqv=V&ech=E&pcs=P&fm=F&type=grpc&authority=a")
	require.Len(t, warnings, 5)
}

func TestErrors(t *testing.T) {
	t.Parallel()
	for name, link := range map[string]string{
		"empty":             "",
		"not a link":        "hello",
		"scheme":            "gopher://example.org:70",
		"no user":           "vless://example.org:443",
		"empty user":        "vless://@example.org:443",
		"no port":           "vless://" + testUUID + "@example.org",
		"bad port":          "vless://" + testUUID + "@example.org:70000",
		"zero port":         "vless://" + testUUID + "@example.org:0",
		"no host":           "vless://" + testUUID + "@:443",
		"bad ipv6":          "vless://" + testUUID + "@[::1:443",
		"encryption":        "vless://" + testUUID + "@example.org:443?encryption=mlkem768x25519plus.native.0rtt.KEY",
		"security":          "vless://" + testUUID + "@example.org:443?security=xtls",
		"reality no key":    "vless://" + testUUID + "@example.org:443?security=reality",
		"kcp":               "vless://" + testUUID + "@example.org:443?type=kcp",
		"tcp http header":   "vless://" + testUUID + "@example.org:443?security=tls&type=tcp&headerType=http",
		"tcp other header":  "vless://" + testUUID + "@example.org:443?type=tcp&headerType=srtp",
		"grpc mode":         "vless://" + testUUID + "@example.org:443?type=grpc&mode=other",
		"bad escape":        "vless://" + testUUID + "@example.org:443?type=ws&path=%zz",
		"extra not json":    xhttpLink(`{"xPaddingBytes":`, url.QueryEscape, ""),
		"extra not object":  xhttpLink(`"text"`, url.QueryEscape, ""),
		"extra bad range":   xhttpLink(`{"xPaddingBytes":"a-b"}`, url.QueryEscape, ""),
		"extra huge range":  xhttpLink(`{"xPaddingBytes":99999999999}`, url.QueryEscape, ""),
		"extra bad type":    xhttpLink(`{"noGRPCHeader":"yes"}`, url.QueryEscape, ""),
		"flat padding":      xhttpLink(`{}`, url.QueryEscape, "&x_padding_bytes=a%22b"),
		"extra bad headers": xhttpLink(`{"headers":{"a":1}}`, url.QueryEscape, ""),
	} {
		outbound, _, err := Decode(link)
		require.Error(t, err, name)
		require.Nil(t, outbound, name)
		// a link is a secret: the error does not repeat it
		require.NotContains(t, err.Error(), testUUID, name)
	}
}

// What the decoder writes is a configuration the strict reader takes back unchanged.
func TestRoundTrip(t *testing.T) {
	t.Parallel()
	extra := `{"xPaddingBytes":"100-1000","xPaddingObfsMode":true,"xPaddingKey":"k","xPaddingHeader":"X-P","xPaddingPlacement":"header","xPaddingMethod":"tokenish",` +
		`"uplinkHTTPMethod":"PUT","sessionIDPlacement":"header","sessionIDKey":"X-S","sessionIDTable":"abc","sessionIDLength":"8-16","seqPlacement":"query","seqKey":"q",` +
		`"uplinkDataPlacement":"cookie","uplinkDataKey":"d","uplinkChunkSize":"100-200","noGRPCHeader":true,"noSSEHeader":true,"scMaxEachPostBytes":"1-2",` +
		`"scMinPostsIntervalMs":3,"scMaxBufferedPosts":4,"scStreamUpServerSecs":"5-6","serverMaxHeaderBytes":7,"headers":{"A":"b"},` +
		`"xmux":{"maxConcurrency":1,"maxConnections":2,"cMaxReuseTimes":3,"hMaxRequestTimes":4,"hMaxReusableSecs":5,"hKeepAlivePeriod":6},` +
		`"downloadSettings":{"address":"d.example.org","port":443,"security":"tls","tlsSettings":{"alpn":"h3,h2","allowInsecure":true},"xhttpSettings":{"path":"/d","xmux":{"maxConnections":2}}}}`
	outbound, warnings, err := Decode(xhttpLink(extra, url.QueryEscape, ""))
	require.NoError(t, err)
	require.Empty(t, warnings)
	want := *optionsOf[option.VLESSOutboundOptions](t, outbound).Transport
	content, err := json.Marshal(want)
	require.NoError(t, err)
	var got option.V2RayTransportOptions
	require.NoError(t, json.UnmarshalDisallowUnknownFields(content, &got))
	require.Equal(t, want, got)
	require.Equal(t, []string{"h3", "h2"}, []string(got.XHTTPOptions.Download.TLS.ALPN))
}

func FuzzDecode(f *testing.F) {
	f.Add(xhttpLink(`{"xPaddingBytes":"100-1000","xmux":{"maxConcurrency":"16-32"},"downloadSettings":{"address":"a","port":1}}`, url.QueryEscape, ""))
	f.Add("trojan://p@example.org:443?type=ws&path=%2Fws%3Fed%3D2560#n")
	f.Add("vless://u@[::1]:1?security=reality&pbk=k&type=grpc")
	f.Fuzz(func(t *testing.T, link string) {
		outbound, _, err := Decode(link)
		if err != nil {
			return
		}
		_, err = json.Marshal(outbound)
		if err != nil {
			t.Fatal(err)
		}
	})
}

// The forms found in links in the wild: other cases and names of the
// parameters, links copied out of HTML, settings of XHTTP outside of "extra".
func TestFoundInTheWild(t *testing.T) {
	t.Parallel()
	base := "vless://" + testUUID + "@example.org:443?"
	for name, test := range map[string]struct{ link, want string }{
		"case and other names": {
			base + "security=tls&allowinsecure=1&servername=s.example.org&packet-encoding=xudp&type=Tcp&headertype=none",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","packet_encoding":"xudp","tls":{"enabled":true,"server_name":"s.example.org","insecure":true,"utls":{"enabled":true,"fingerprint":"chrome"}}}`,
		},
		"clash names": {
			base + "security=tls&allow_insecure=1&peer=p.example.org",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","tls":{"enabled":true,"server_name":"p.example.org","insecure":true,"utls":{"enabled":true,"fingerprint":"chrome"}}}`,
		},
		"copied out of HTML": {
			base + "security=tls&amp;type=ws&amp;path=%2Fw&amp;Host=h.example.org",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"}},"transport":{"type":"ws","path":"/w","headers":{"Host":"h.example.org"}}}`,
		},
		"password with a slash": {
			"trojan://Km/pIG4A+j5==@example.org:443/?type=ws&path=/w&ed=2048&eh=X-Early",
			`{"type":"trojan","server":"example.org","server_port":443,"password":"Km/pIG4A+j5==","tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"}},
			"transport":{"type":"ws","path":"/w","max_early_data":2048,"early_data_header_name":"X-Early"}}`,
		},
		"flat xhttp settings": {
			base + "type=xhttp&path=%2Fx&xPaddingBytes=5-9&noGRPCHeader=true&scMaxBufferedPosts=7&sessionIDKey=k&uplinkHTTPMethod=PUT",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","transport":{"type":"xhttp","path":"/x",
			"x_padding_bytes":"5-9","no_grpc_header":true,"sc_max_buffered_posts":7,"session_key":"k","uplink_http_method":"PUT"}}`,
		},
		"extra before flat settings": {
			base + "type=xhttp&xPaddingBytes=5-9&scMaxEachPostBytes=100&extra=" + url.QueryEscape(`{"xPaddingBytes":"1-2"}`),
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","transport":{"type":"xhttp","x_padding_bytes":"1-2","sc_max_each_post_bytes":"100"}}`,
		},
		"mode of v2rayA": {
			base + "type=xhttp&xhttpMode=stream-up",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","transport":{"type":"xhttp","mode":"stream-up"}}`,
		},
		"extra escaped twice, a number with a fraction": {
			base + "type=xhttp&extra=" + url.QueryEscape(uriComponent(`{"scMinPostsIntervalMs":30.0,"xmux":{"maxConnections":2.0}}`)),
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","transport":{"type":"xhttp","sc_min_posts_interval_ms":"30","xmux":{"max_connections":"2"}}}`,
		},
	} {
		content, warnings := decodeJSON(t, test.link)
		require.Empty(t, warnings, name)
		require.JSONEq(t, test.want, content, name)
	}

	_, warnings := decodeJSON(t, base+"type=xhttp&mux=1&pinSHA256=x&spx=%2F&extra="+url.QueryEscape(`{"xmux":{"cMaxLifetimeMs":5,"maxConnections":1}}`))
	// pinSHA256 belongs to TLS, which this link does not have: nothing to warn of
	require.Equal(t, []string{"extra.xmux: cMaxLifetimeMs is not supported and is ignored", "mux is not supported and is ignored"}, warnings)

	for name, link := range map[string]string{
		"flat range":      base + "type=xhttp&xPaddingBytes=a-b",
		"flat number":     base + "type=xhttp&scMaxBufferedPosts=many",
		"fraction":        base + "type=xhttp&extra=" + url.QueryEscape(`{"scMinPostsIntervalMs":30.5}`),
		"xmux not object": base + "type=xhttp&extra=" + url.QueryEscape(`{"xmux":[1]}`),
	} {
		_, _, err := Decode(link)
		require.Error(t, err, name)
	}
}

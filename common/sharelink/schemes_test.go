package sharelink

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func b64(text string) string {
	return base64.StdEncoding.EncodeToString([]byte(text))
}

func b64url(text string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(text))
}

// The schemes besides VLESS and Trojan, each in the forms its generators write.
func TestSchemes(t *testing.T) {
	t.Parallel()
	const key2022 = "dmCly/Zh15Ww9+s+GFXiFTIkpw7c/qCISaBrai7WhhY="
	for name, test := range map[string]struct {
		link     string
		want     string
		warnings []string
	}{
		"shadowsocks, SIP002 with base64": {
			"ss://" + b64url("aes-256-gcm:pass:word") + "@example.org:8388#%D0%B8%D0%BC%D1%8F",
			`{"type":"shadowsocks","tag":"имя","server":"example.org","server_port":8388,"method":"aes-256-gcm","password":"pass:word"}`, nil,
		},
		"shadowsocks, padded base64 and a slash": {
			"ss://" + b64("chacha20-ietf-poly1305:p") + "@[2001:db8::1]:8388/?type=tcp",
			`{"type":"shadowsocks","server":"2001:db8::1","server_port":8388,"method":"chacha20-ietf-poly1305","password":"p"}`, nil,
		},
		"shadowsocks 2022, not escaped": {
			"ss://2022-blake3-aes-256-gcm:" + key2022 + "@127.0.0.1:27214?type=tcp#plain",
			`{"type":"shadowsocks","tag":"plain","server":"127.0.0.1","server_port":27214,"method":"2022-blake3-aes-256-gcm","password":"` + key2022 + `"}`, nil,
		},
		"shadowsocks 2022, escaped, with a user key": {
			"ss://2022-blake3-aes-256-gcm:" + uriComponent(key2022+":"+key2022) + "@127.0.0.1:27214",
			`{"type":"shadowsocks","server":"127.0.0.1","server_port":27214,"method":"2022-blake3-aes-256-gcm","password":"` + key2022 + ":" + key2022 + `"}`, nil,
		},
		"shadowsocks, the older form": {
			"ss://" + b64("aes-128-gcm:p%ss@example.org:8388") + "#old",
			`{"type":"shadowsocks","tag":"old","server":"example.org","server_port":8388,"method":"aes-128-gcm","password":"p%ss"}`, nil,
		},
		"shadowsocks with a plugin, UDP over TCP and an older method name": {
			"ss://" + b64url("chacha20-poly1305:p") + "@example.org:8388/?plugin=simple-obfs%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com&uot=1",
			`{"type":"shadowsocks","server":"example.org","server_port":8388,"method":"chacha20-ietf-poly1305","password":"p","plugin":"obfs-local","plugin_opts":"obfs=http;obfs-host=example.com","udp_over_tcp":true}`, nil,
		},
		"socks5 with a user": {
			"socks5://user:p%40ss@127.0.0.1:1080#s",
			`{"type":"socks","tag":"s","server":"127.0.0.1","server_port":1080,"username":"user","password":"p@ss"}`, nil,
		},
		"socks4a without a port": {
			"socks4a://proxy.example.org",
			`{"type":"socks","server":"proxy.example.org","server_port":1080,"version":"4a"}`, nil,
		},
		"socks4": {
			"socks4://127.0.0.1:1080",
			`{"type":"socks","server":"127.0.0.1","server_port":1080,"version":"4"}`, nil,
		},
		"socks5h": {
			"socks5h://127.0.0.1:1080",
			`{"type":"socks","server":"127.0.0.1","server_port":1080}`, nil,
		},
		"socks of v2rayN, the user in base64": {
			"socks://" + b64("user:pass") + "@127.0.0.1:1080#n",
			`{"type":"socks","tag":"n","server":"127.0.0.1","server_port":1080,"username":"user","password":"pass"}`, nil,
		},
		"hysteria2, everything": {
			"hysteria2://my%3Apassword@example.com:8443/?sni=sni.example.com&obfs=salamander&obfs-password=obfspass&insecure=1&alpn=h3#all",
			`{"type":"hysteria2","tag":"all","server":"example.com","server_port":8443,"obfs":{"type":"salamander","password":"obfspass"},"password":"my:password",
			"tls":{"enabled":true,"server_name":"sni.example.com","insecure":true,"alpn":"h3"}}`, nil,
		},
		"hy2 without a port or a password": {
			"hy2://example.com",
			`{"type":"hysteria2","server":"example.com","server_port":443,"tls":{"enabled":true}}`, nil,
		},
		"hysteria2 with a list of ports and speeds": {
			"hysteria2://p@example.com:443,5000-6000/?upmbps=50&down=200%20Mbps&pinSHA256=AB%3ACD",
			`{"type":"hysteria2","server":"example.com","server_port":443,"server_ports":["443:443","5000:6000"],"up_mbps":50,"down_mbps":200,"password":"p","tls":{"enabled":true}}`,
			[]string{"the pinned certificate (pcs, pinSHA256) is not supported"},
		},
		"hysteria2 with mport": {
			"hysteria2://p@[2001:db8::1]:443?mport=20000-30000",
			`{"type":"hysteria2","server":"2001:db8::1","server_port":443,"server_ports":"20000:30000","password":"p","tls":{"enabled":true}}`, nil,
		},
		"hysteria2 of Remnawave: obfuscation, port hopping and speeds in fm": {
			"hysteria2://p@example.com:443/?sni=s.example.com&fm=" + uriComponent(`{"udp":[{"type":"salamander","settings":{"password":"obfs pass"}},{"type":"noise"}],"quicParams":{"brutalUp":"50 mbps","brutalDown":200,"udpHop":{"ports":"20000-30000,40000","interval":"10-30"}}}`),
			`{"type":"hysteria2","server":"example.com","server_port":443,"server_ports":["20000:30000","40000:40000"],"hop_interval":"10s","up_mbps":50,"down_mbps":200,
			"obfs":{"type":"salamander","password":"obfs pass"},"password":"p","tls":{"enabled":true,"server_name":"s.example.com"}}`, nil,
		},
		"hysteria2 with fm that says what the link says already": {
			"hysteria2://p@example.com:443/?obfs=salamander&obfs-password=link&mport=5000-6000&fm=" + uriComponent(`{"udp":[{"type":"salamander","settings":{"password":"mask"}}],"quicParams":{"udpHop":{"ports":"1-2"}}}`),
			`{"type":"hysteria2","server":"example.com","server_port":443,"server_ports":"5000:6000","obfs":{"type":"salamander","password":"link"},"password":"p","tls":{"enabled":true}}`, nil,
		},
		"vmess of Marzban: gRPC with type none, an IPv6 address in brackets": {
			"vmess://" + b64(`{"add": "[2001:db8::10]", "aid": "0", "host": "", "id": "`+testUUID+`", "net": "grpc", "path": "svc", "port": 443, "ps": "m", "scy": "auto", "tls": "tls", "type": "none", "v": "2"}`),
			`{"type":"vmess","tag":"m","server":"2001:db8::10","server_port":443,"uuid":"` + testUUID + `","security":"auto","tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"}},"transport":{"type":"grpc","service_name":"svc"}}`, nil,
		},
		"tuic": {
			"tuic://" + testUUID + ":pass%3Aword@example.org:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=s.example.org&allow_insecure=1&disable_sni=1&reduce_rtt=1&heartbeat_interval=10#t",
			`{"type":"tuic","tag":"t","server":"example.org","server_port":443,"uuid":"` + testUUID + `","password":"pass:word","congestion_control":"bbr","udp_relay_mode":"native",
			"zero_rtt_handshake":true,"heartbeat":"10s","tls":{"enabled":true,"disable_sni":true,"server_name":"s.example.org","insecure":true,"alpn":"h3"}}`, nil,
		},
		"vmess of v2rayN, ws with TLS": {
			"vmess://" + b64(`{"v":"2","ps":"имя","add":"example.org","port":"443","id":"`+testUUID+`","aid":"0","scy":"auto","net":"ws","type":"none","host":"h.example.org","path":"/ws?ed=2048","tls":"tls","sni":"s.example.org","alpn":"http/1.1","fp":"firefox"}`),
			`{"type":"vmess","tag":"имя","server":"example.org","server_port":443,"uuid":"` + testUUID + `","security":"auto",
			"tls":{"enabled":true,"server_name":"s.example.org","utls":{"enabled":true,"fingerprint":"firefox"}},
			"transport":{"type":"ws","path":"/ws","headers":{"Host":"h.example.org"},"max_early_data":2048,"early_data_header_name":"Sec-WebSocket-Protocol"}}`, nil,
		},
		"vmess of v2rayN, numbers as numbers, grpc": {
			"vmess://" + b64url(`{"v":2,"ps":"g","add":"192.0.2.1","port":8443,"id":"`+testUUID+`","aid":1,"net":"grpc","type":"multi","path":"svc","tls":""}`),
			`{"type":"vmess","tag":"g","server":"192.0.2.1","server_port":8443,"uuid":"` + testUUID + `","security":"auto","alter_id":1,"transport":{"type":"grpc","service_name":"svc"}}`,
			[]string{"the gRPC mode multi is not supported, gun is used"},
		},
		"vmess of v2rayN, tcp with an HTTP header": {
			"vmess://" + b64(`{"ps":"h","add":"192.0.2.1","port":"80","id":"`+testUUID+`","scy":"aes-128-gcm","net":"tcp","type":"http","host":"a.example.org","path":"/"}`),
			`{"type":"vmess","tag":"h","server":"192.0.2.1","server_port":80,"uuid":"` + testUUID + `","security":"aes-128-gcm","transport":{"type":"http","host":"a.example.org","path":"/"}}`, nil,
		},
		"vmess as a URL": {
			"vmess://" + testUUID + "@example.org:443?type=httpupgrade&security=tls&encryption=chacha20-poly1305&host=h.example.org&path=%2Fu&alterId=0#u",
			`{"type":"vmess","tag":"u","server":"example.org","server_port":443,"uuid":"` + testUUID + `","security":"chacha20-poly1305",
			"tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"}},"transport":{"type":"httpupgrade","host":"h.example.org","path":"/u"}}`, nil,
		},
		"http proxy": {
			"http://user:p%20ss@proxy.example.org:3128/#h",
			`{"type":"http","tag":"h","server":"proxy.example.org","server_port":3128,"username":"user","password":"p ss"}`, nil,
		},
		"https proxy": {
			"https://proxy.example.org:8443?sni=s.example.org",
			`{"type":"http","server":"proxy.example.org","server_port":8443,"tls":{"enabled":true,"server_name":"s.example.org"}}`, nil,
		},
		"hysteria": {
			"hysteria://example.org:36712?protocol=udp&auth=secret&peer=s.example.org&insecure=1&upmbps=10&downmbps=50&alpn=hysteria&obfs=xplus&obfsParam=obfs#v1",
			`{"type":"hysteria","tag":"v1","server":"example.org","server_port":36712,"up_mbps":10,"down_mbps":50,"obfs":"obfs","auth_str":"secret",
			"tls":{"enabled":true,"server_name":"s.example.org","insecure":true,"alpn":"hysteria"}}`, nil,
		},
		"anytls": {
			"anytls://pass%2Fword@example.org/?sni=s.example.org&insecure=1#a",
			`{"type":"anytls","tag":"a","server":"example.org","server_port":443,"tls":{"enabled":true,"server_name":"s.example.org","insecure":true},"password":"pass/word"}`, nil,
		},
		"anytls with a fingerprint": {
			"anytls://p@example.org:8443?fp=chrome",
			`{"type":"anytls","server":"example.org","server_port":8443,"tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"}},"password":"p"}`, nil,
		},
		"naive over HTTPS": {
			"naive+https://user:pass@example.org?sni=s.example.org&extra-headers=X-A%3A%20one%0D%0AX-B%3A%20two&insecure-concurrency=2#n",
			`{"type":"naive","tag":"n","server":"example.org","server_port":443,"username":"user","password":"pass","insecure_concurrency":2,
			"extra_headers":{"X-A":"one","X-B":"two"},"tls":{"enabled":true,"server_name":"s.example.org"}}`, nil,
		},
		"naive over QUIC": {
			"naive+quic://user:pass@example.org:8443",
			`{"type":"naive","server":"example.org","server_port":8443,"username":"user","password":"pass","quic":true,"tls":{"enabled":true}}`, nil,
		},
	} {
		content, warnings := decodeJSON(t, test.link)
		require.JSONEq(t, test.want, content, name)
		require.Len(t, warnings, len(test.warnings), "%s: %v", name, warnings)
		for index, warning := range test.warnings {
			require.Contains(t, warnings[index], warning, name)
		}
	}
}

func TestSchemeRefusals(t *testing.T) {
	t.Parallel()
	for link, id := range map[string]string{
		"ss://" + b64url("aes-256-gcm:p") + "@example.org:443?type=ws&path=%2Fw": "shadowsocks-transport",
		"ss://" + b64url("aes-256-gcm:p") + "@example.org:443?security=tls":      "shadowsocks-transport",
		"ss://" + b64url("aes-256-gcm:p") + "@example.org:443?headerType=http":   "shadowsocks-transport",
		"https://example.org":                       "http-not-a-proxy",
		"https://example.org/sub/TOKEN":             "http-not-a-proxy",
		"http://user:pass@example.org:8080/path":    "http-not-a-proxy",
		"hysteria://example.org:1?protocol=faketcp": "hysteria-protocol",
		"hysteria://example.org:1?obfs=salamander":  "hysteria-obfs",
		"tuic://token@example.org:443":              "tuic-v4",
		"vmess://" + b64(`{"add":"h","port":1,"id":"`+testUUID+`","net":"kcp","type":"none","path":"seed"}`):        "kcp",
		"vmess://" + b64(`{"add":"h","port":1,"id":"`+testUUID+`","net":"quic","host":"aes-128-gcm","path":"key"}`): "quic-security",
		"hysteria2://p@example.org?fm=" + uriComponent(`{"udp":[{"type":"xdns"}]}`):                                 "finalmask",
	} {
		require.Equal(t, id, refusalID(t, link), link)
	}
	for name, link := range map[string]string{
		"shadowsocks without a method": "ss://" + b64url("justapassword") + "@example.org:443",
		"shadowsocks, not base64":      "ss://not_base64_at_all!!!",
		"vmess, neither form":          "vmess://nothing-here",
		"vmess without an address":     "vmess://" + b64(`{"port":1,"id":"`+testUUID+`"}`),
		"vmess with a bad port":        "vmess://" + b64(`{"add":"h","port":"x","id":"`+testUUID+`"}`),
		"vmess JSON with an object":    "vmess://" + b64(`{"add":{"a":1},"port":1,"id":"x"}`),
		"hysteria2 with a bad port":    "hysteria2://p@example.org:0",
		"hysteria2 with bad ports":     "hysteria2://p@example.org:443,x-y",
		"socks with a bad port":        "socks5://127.0.0.1:99999",
	} {
		outbound, _, err := Decode(link)
		require.Error(t, err, name)
		require.Nil(t, outbound, name)
	}
}

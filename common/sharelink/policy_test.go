package sharelink

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Every refusal of the decoder is a row of the policy table, and every row is used.
func TestPolicyTable(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	used := make(map[string]bool)
	pattern := regexp.MustCompile(`refuse\("([a-z0-9-]+)"`)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		content, err := os.ReadFile(entry.Name())
		require.NoError(t, err)
		for _, match := range pattern.FindAllSubmatch(content, -1) {
			used[string(match[1])] = true
		}
	}
	require.NotEmpty(t, used)
	for id := range used {
		require.Contains(t, refusals, id, "a refusal without a row in the policy table")
	}
	for id, reason := range refusals {
		require.True(t, used[id], "the policy table has a row nothing uses: %s", id)
		require.NotEmpty(t, reason, id)
	}
}

func refusalID(t *testing.T, link string) string {
	t.Helper()
	outbound, _, err := Decode(link)
	require.Error(t, err, link)
	require.Nil(t, outbound, link)
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		return "(not a refusal) " + err.Error()
	}
	return refusal.ID
}

const policyBase = "vless://" + testUUID + "@example.org:443?"

// What a link asks for and sing-box cannot do, where the server is not reached without
// it: each is refused under its rule.
func TestRefusals(t *testing.T) {
	t.Parallel()
	for link, id := range map[string]string{
		"tor://example.org:9050":                                                                      "no-link-form",
		"ssh://user:pass@example.org:22":                                                              "no-link-form",
		"shadowtls://x@example.org:443":                                                               "no-link-form",
		"snell://x@example.org:443":                                                                   "no-link-form",
		policyBase + "security=xtls":                                                                  "security",
		policyBase + "encryption=mlkem768x25519plus.native.0rtt.KEY":                                  "vless-encryption",
		policyBase + "security=reality&pbk=K&flow=xtls-rprx-direct":                                   "flow",
		policyBase + "security=tls&flow=xtls-rprx-vision&type=ws":                                     "flow-transport",
		policyBase + "security=tls&flow=xtls-rprx-vision&type=grpc":                                   "flow-transport",
		policyBase + "security=tls&flow=xtls-rprx-vision&type=http":                                   "flow-transport",
		policyBase + "security=tls&flow=xtls-rprx-vision&type=httpupgrade":                            "flow-transport",
		policyBase + "security=tls&flow=xtls-rprx-vision&type=xhttp":                                  "flow-transport",
		policyBase + "security=none&flow=xtls-rprx-vision":                                            "flow-no-tls",
		policyBase + "security=reality&pbk=K&fp=netscape":                                             "fingerprint-reality",
		policyBase + "security=tls&fm=%7B%22tcp%22%3A%5B%7B%22type%22%3A%22header-custom%22%7D%5D%7D": "finalmask",
		policyBase + "security=tls&fm=%7B%22udp%22%3A%5B%7B%22type%22%3A%22salamander%22%7D%5D%7D":    "finalmask",
		policyBase + "security=tls&type=tcp&headerType=http":                                          "tcp-http-header-tls",
		policyBase + "type=tcp&headerType=srtp":                                                       "tcp-header",
		policyBase + "type=grpc&mode=other":                                                           "grpc-mode",
		policyBase + "type=grpc&serviceName=%2Fa%2Fb%2FTun":                                           "grpc-custom-path",
		policyBase + "type=grpc&serviceName=%2Fsvc%2FOther":                                           "grpc-custom-path",
		policyBase + "type=grpc&serviceName=%2Fsvc%2FTun&mode=multi":                                  "grpc-custom-path",
		policyBase + "type=quic&quicSecurity=aes-128-gcm&key=k":                                       "quic-security",
		policyBase + "type=quic&headerType=wechat-video":                                              "quic-header",
		policyBase + "type=kcp&seed=s":                                                                "kcp",
		"trojan://p@example.org:443?type=tcp&headerType=http":                                         "tcp-http-header-tls",
	} {
		require.Equal(t, id, refusalID(t, link), link)
	}
}

// What only the client decides, or what only adds a check: the outbound is made, with a
// warning.
func TestLeniencies(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		link     string
		want     string
		warnings []string
	}{
		"a value of encryption that is not one": {
			policyBase + "encryption=aes-128-gcm",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `"}`,
			[]string{"encryption has a value that is not VLESS encryption"},
		},
		"gRPC multi": {
			policyBase + "type=grpc&serviceName=svc&mode=multi",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","transport":{"type":"grpc","service_name":"svc"}}`,
			[]string{"the gRPC mode multi is not supported, gun is used"},
		},
		"gRPC custom path of the usual shape": {
			policyBase + "type=grpc&serviceName=%2Fsvc%2FTun%7CMulti",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","transport":{"type":"grpc","service_name":"svc"}}`,
			nil,
		},
		"the HTTP header of TCP without TLS": {
			policyBase + "type=tcp&headerType=http&host=a.example.org,b.example.org&path=%2Fp",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","transport":{"type":"http","host":["a.example.org","b.example.org"],"path":"/p"}}`,
			nil,
		},
		"ws without host takes the name of TLS": {
			"vless://" + testUUID + "@192.0.2.1:443?security=tls&sni=cdn.example.org&type=ws&path=%2Fws",
			`{"type":"vless","server":"192.0.2.1","server_port":443,"uuid":"` + testUUID + `","tls":{"enabled":true,"server_name":"cdn.example.org","utls":{"enabled":true,"fingerprint":"chrome"}},
			"transport":{"type":"ws","path":"/ws","headers":{"Host":"cdn.example.org"}}}`,
			nil,
		},
		"trojan ws without host": {
			"trojan://p@192.0.2.1:443?sni=cdn.example.org&type=ws",
			`{"type":"trojan","server":"192.0.2.1","server_port":443,"password":"p","tls":{"enabled":true,"server_name":"cdn.example.org","utls":{"enabled":true,"fingerprint":"chrome"}},
			"transport":{"type":"ws","headers":{"Host":"cdn.example.org"}}}`,
			nil,
		},
		"ws without TLS and host": {
			policyBase + "type=ws&path=%2Fws",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","transport":{"type":"ws","path":"/ws"}}`,
			nil,
		},
		"httpupgrade with early data in the path": {
			policyBase + "type=httpupgrade&path=%2Fu%3Fed%3D2560",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","transport":{"type":"httpupgrade","path":"/u"}}`,
			[]string{"early data is not supported with the httpupgrade transport"},
		},
		"http with a method": {
			policyBase + "security=tls&type=h2&host=h.example.org&path=%2Fh&method=GET",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"}},
			"transport":{"type":"http","host":"h.example.org","path":"/h","method":"GET"}}`,
			nil,
		},
		"quic": {
			policyBase + "security=tls&type=quic&quicSecurity=none&headerType=none",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"}},"transport":{"type":"quic"}}`,
			nil,
		},
		"finalmask of the client's own": {
			policyBase + "fm=%7B%22tcp%22%3A%5B%7B%22type%22%3A%22fragment%22%7D%5D%2C%22udp%22%3A%5B%7B%22type%22%3A%22noise%22%7D%5D%2C%22quicParams%22%3A%7B%7D%7D",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `"}`,
			[]string{"fm (finalmask) is not supported and is ignored"},
		},
		"finalmask that cannot be read": {
			policyBase + "fm=x",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `"}`,
			[]string{"fm (finalmask) is not supported and cannot be read"},
		},
		"packet as packetaddr": {
			policyBase + "packetEncoding=packet",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","packet_encoding":"packetaddr"}`,
			nil,
		},
		"a pinned certificate": {
			policyBase + "security=tls&pcs=0123abcd&vcn=example.org",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"}}}`,
			[]string{"the pinned certificate (pcs, pinSHA256) is not supported", "vcn is not supported and is ignored"},
		},
		"a pinned certificate, not verified anyway": {
			policyBase + "security=tls&pcs=0123abcd&allowInsecure=1",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","tls":{"enabled":true,"insecure":true,"utls":{"enabled":true,"fingerprint":"chrome"}}}`,
			nil,
		},
		"ECH configuration": {
			policyBase + "security=tls&ech=AEX+DQBBFQAgACDcTtW6VmPQkAvAnqIbGkSmKuOO+GbBdXvKkcOIAfS0PAAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"},
			"ech":{"enabled":true,"config":["-----BEGIN ECH CONFIGS-----","AEX+DQBBFQAgACDcTtW6VmPQkAvAnqIbGkSmKuOO+GbBdXvKkcOIAfS0PAAEAAEA","AQASY2xvdWRmbGFyZS1lY2guY29tAAA=","-----END ECH CONFIGS-----"]}}}`,
			nil,
		},
		"ECH from DNS": {
			policyBase + "security=tls&ech=ech.example.org%2Bhttps%3A%2F%2F1.1.1.1%2Fdns-query",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"},
			"ech":{"enabled":true,"query_server_name":"ech.example.org"}}}`,
			[]string{"the resolver named in ech is not used"},
		},
		"no SNI and a certificate to trust": {
			policyBase + "security=tls&disable_sni=1&cert=-----BEGIN%20CERTIFICATE-----%0AMIIB%0A-----END%20CERTIFICATE-----",
			`{"type":"vless","server":"example.org","server_port":443,"uuid":"` + testUUID + `","tls":{"enabled":true,"disable_sni":true,
			"certificate":["-----BEGIN CERTIFICATE-----","MIIB","-----END CERTIFICATE-----"],"utls":{"enabled":true,"fingerprint":"chrome"}}}`,
			nil,
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

// The user of a VLESS link, as Xray reads it.
func TestVLESSUser(t *testing.T) {
	t.Parallel()
	for user, want := range map[string]string{
		testUUID:                              testUUID,
		strings.ToUpper(testUUID):             testUUID,
		strings.ReplaceAll(testUUID, "-", ""): testUUID,
		// dashes are optional one by one
		"6f1c9a0e-3b524c1e9a552d4a1b0f7c11": testUUID,
		"my-user":                           "my-user",
		"thirty-bytes-are-the-longest-1":    "thirty-bytes-are-the-longest-1",
	} {
		outbound, _, err := Decode("vless://" + user + "@h:1")
		require.NoError(t, err, user)
		require.Equal(t, want, outbound.options.text("uuid"), user)
	}
	for _, user := range []string{
		"thirty-one-bytes-are-too-many-1",
		"6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c1",   // 35 with a digit missing
		"6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7cXY",  // not hexadecimal
		"6f1c9a0e--3b52-4c1e-9a55-2d4a1b0f7c1",  // a dash too many
		"6f1c9a0e-3b52-4c1e-9a55-2d4a1b0f7c11a", // 37
	} {
		_, _, err := Decode("vless://" + user + "@h:1")
		require.ErrorContains(t, err, "not a UUID", user)
	}
}

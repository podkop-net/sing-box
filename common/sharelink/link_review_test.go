package sharelink

import (
	"context"
	"net/url"
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

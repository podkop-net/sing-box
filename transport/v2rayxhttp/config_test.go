package v2rayxhttp

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func xrange(from, to int32) *option.V2RayXHTTPRange {
	return &option.V2RayXHTTPRange{From: from, To: to}
}

// What Xray refuses, and what it panics on at a dial, fails here when the
// client is built, which `sing-box check` does.
func TestXHTTPConfigErrors(t *testing.T) {
	cases := map[string]func(*option.V2RayXHTTPOptions){
		"unknown mode": func(o *option.V2RayXHTTPOptions) { o.Mode = "stream-down" },
		"download in stream-one": func(o *option.V2RayXHTTPOptions) {
			o.Mode, o.Download = modeStreamOne, &option.V2RayXHTTPDownloadOptions{}
		},
		"download without server":    func(o *option.V2RayXHTTPOptions) { o.Download = &option.V2RayXHTTPDownloadOptions{} },
		"host in headers":            func(o *option.V2RayXHTTPOptions) { o.Headers = badoption.HTTPHeader{"Host": {"a"}} },
		"padding disabled":           func(o *option.V2RayXHTTPOptions) { o.XPaddingBytes = xrange(0, 100) },
		"padding negative":           func(o *option.V2RayXHTTPOptions) { o.XPaddingBytes = xrange(-1, -1) },
		"padding huge":               func(o *option.V2RayXHTTPOptions) { o.XPaddingBytes = xrange(100, 1<<30) },
		"padding placement":          func(o *option.V2RayXHTTPOptions) { o.XPaddingPlacement = "body" },
		"padding method":             func(o *option.V2RayXHTTPOptions) { o.XPaddingMethod = "random" },
		"GET upload with auto mode":  func(o *option.V2RayXHTTPOptions) { o.UplinkHTTPMethod = "get" },
		"data in headers, stream-up": func(o *option.V2RayXHTTPOptions) { o.Mode, o.UplinkDataPlacement = modeStreamUp, placementHeader },
		"data in cookies, auto":      func(o *option.V2RayXHTTPOptions) { o.UplinkDataPlacement = placementCookie },
		"data placement":             func(o *option.V2RayXHTTPOptions) { o.UplinkDataPlacement = "query" },
		"session placement":          func(o *option.V2RayXHTTPOptions) { o.SessionPlacement = "body" },
		"seq placement":              func(o *option.V2RayXHTTPOptions) { o.SeqPlacement = "queryInHeader" },
		"session table too small":    func(o *option.V2RayXHTTPOptions) { o.SessionIDTable, o.SessionIDLength = "number", xrange(4, 8) },
		"session length zero":        func(o *option.V2RayXHTTPOptions) { o.SessionIDTable, o.SessionIDLength = "hex", xrange(0, 32) },
		"session length huge":        func(o *option.V2RayXHTTPOptions) { o.SessionIDTable, o.SessionIDLength = "hex", xrange(16, 1<<30) },
		"session table not ASCII": func(o *option.V2RayXHTTPOptions) {
			o.SessionIDTable, o.SessionIDLength = "абвгдежзиклмнопр", xrange(16, 16)
		},
		"post size negative":  func(o *option.V2RayXHTTPOptions) { o.ScMaxEachPostBytes = xrange(-1, -1) },
		"post size from zero": func(o *option.V2RayXHTTPOptions) { o.ScMaxEachPostBytes = xrange(0, 1000) },
		"connections and concurrency": func(o *option.V2RayXHTTPOptions) {
			o.Xmux = &option.V2RayXHTTPXmuxOptions{MaxConnections: xrange(2, 2), MaxConcurrency: xrange(4, 4)}
		},
		"header name":    func(o *option.V2RayXHTTPOptions) { o.Headers = badoption.HTTPHeader{"X Foo": {"a"}} },
		"header value":   func(o *option.V2RayXHTTPOptions) { o.Headers = badoption.HTTPHeader{"X-Foo": {"a\nb"}} },
		"upgrade header": func(o *option.V2RayXHTTPOptions) { o.Headers = badoption.HTTPHeader{"Upgrade": {"websocket"}} },
		"session key":    func(o *option.V2RayXHTTPOptions) { o.SessionPlacement, o.SessionKey = placementHeader, "X Session" },
		"cookie key":     func(o *option.V2RayXHTTPOptions) { o.SessionPlacement, o.SessionKey = placementCookie, "a=b; c" },
		"padding header": func(o *option.V2RayXHTTPOptions) { o.XPaddingHeader = "X:Pad" },
		"session table with a slash": func(o *option.V2RayXHTTPOptions) {
			o.SessionIDTable, o.SessionIDLength = "ABCDEFGHIJKLMNOP+/", xrange(16, 16)
		},
		"download padding": func(o *option.V2RayXHTTPOptions) {
			o.Download = &option.V2RayXHTTPDownloadOptions{ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 1}}
			o.Download.XPaddingBytes = xrange(0, 10)
		},
	}
	for name, configure := range cases {
		options := option.V2RayXHTTPOptions{}
		configure(&options)
		_, err := NewClient(context.Background(), N.SystemDialer, M.ParseSocksaddr("127.0.0.1:443"), options, nil)
		require.Error(t, err, name)
	}
}

func TestXHTTPConfigDefaults(t *testing.T) {
	cases := map[string]func(*option.V2RayXHTTPOptions){
		"empty":                     func(o *option.V2RayXHTTPOptions) {},
		"zero post size is default": func(o *option.V2RayXHTTPOptions) { o.ScMaxEachPostBytes = xrange(0, 0) },
		"negative interval":         func(o *option.V2RayXHTTPOptions) { o.ScMinPostsIntervalMs = xrange(-1, -1) },
		"GET upload in packet-up":   func(o *option.V2RayXHTTPOptions) { o.Mode, o.UplinkHTTPMethod = modePacketUp, "GET" },
		"server-side settings": func(o *option.V2RayXHTTPOptions) {
			o.NoSSEHeader, o.ScMaxBufferedPosts, o.ScStreamUpServerSecs, o.ServerMaxHeaderBytes = true, 30, xrange(20, 80), 8192
		},
	}
	for name, configure := range cases {
		options := option.V2RayXHTTPOptions{}
		configure(&options)
		transport, err := NewClient(context.Background(), N.SystemDialer, M.ParseSocksaddr("127.0.0.1:443"), options, nil)
		require.NoError(t, err, name)
		transport.Close()
	}
	config, err := newRequestConfig(option.V2RayXHTTPBaseOptions{}, modeAuto)
	require.NoError(t, err)
	require.Equal(t, valueRange{100, 1000}, config.paddingBytes)
	require.Equal(t, valueRange{1000000, 1000000}, config.maxEachPostBytes)
	require.Equal(t, valueRange{30, 30}, config.minPostsIntervalMs)
	require.Equal(t, xmuxConfig{maxConnections: valueRange{3, 3}, hMaxRequestTimes: valueRange{600, 900}, hMaxReusableSecs: valueRange{1800, 3000}}, config.xmux)
	require.Equal(t, "/", config.normalizedPath())
	for _, placement := range []string{placementHeader, placementCookie} {
		config, err = newRequestConfig(option.V2RayXHTTPBaseOptions{UplinkDataPlacement: placement}, modePacketUp)
		require.NoError(t, err)
		require.Equal(t, valueRange{4096, 4096}, config.maxEachPostBytes, placement)
		config, err = newRequestConfig(option.V2RayXHTTPBaseOptions{UplinkDataPlacement: placement, ScMaxEachPostBytes: xrange(2048, 2048)}, modePacketUp)
		require.NoError(t, err)
		require.Equal(t, valueRange{2048, 2048}, config.maxEachPostBytes, placement)
	}
	// Setting any XMUX field drops all its defaults, as with Xray.
	config, err = newRequestConfig(option.V2RayXHTTPBaseOptions{Xmux: &option.V2RayXHTTPXmuxOptions{HKeepAlivePeriod: 30}}, modeAuto)
	require.NoError(t, err)
	require.Equal(t, xmuxConfig{hKeepAlivePeriod: 30}, config.xmux)
}

func TestXHTTPPaths(t *testing.T) {
	for _, c := range []struct {
		path, placement, expected string
	}{
		{"", placementPath, "/"},
		{"xhttp", placementPath, "/xhttp/"},
		{"/xhttp", placementPath, "/xhttp/"},
		{"/xhttp/", placementPath, "/xhttp/"},
		{"/xhttp", placementQuery, "/xhttp"},
		{"/xhttp?ed=2048", placementHeader, "/xhttp"},
	} {
		options := option.V2RayXHTTPBaseOptions{Path: c.path, SessionPlacement: c.placement, SeqPlacement: c.placement}
		config, err := newRequestConfig(options, modeAuto)
		require.NoError(t, err)
		require.Equal(t, c.expected, config.normalizedPath(), c.path+" "+c.placement)
	}
}

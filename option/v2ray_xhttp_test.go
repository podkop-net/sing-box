package option

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestV2RayXHTTPRange(t *testing.T) {
	valid := map[string]V2RayXHTTPRange{
		`"100-1000"`:           {100, 1000},
		`"5"`:                  {5, 5},
		`5`:                    {5, 5},
		`""`:                   {0, 0},
		`"-1"`:                 {-1, -1},
		`"-5-10"`:              {-5, 10},
		`"-20--10"`:            {-20, -10},
		`"1000-100"`:           {100, 1000},
		`{"from": 1, "to": 2}`: {1, 2},
		`{"from": 9, "to": 2}`: {2, 9},
		`{"from": 7}`:          {0, 7},
		`"2147483647"`:         {2147483647, 2147483647},
		`"-2147483648-0"`:      {-2147483648, 0},
		`"0-1000"`:             {0, 1000},
		`"10-10"`:              {10, 10},
		`{"to": 3, "from": 3}`: {3, 3},
		`"  "`:                 {},
		`[1, 2]`:               {},
		`"1-2-3"`:              {},
		`"a-b"`:                {},
		`"2147483648"`:         {},
		`{"from": 1, "x": 2}`:  {},
		`true`:                 {},
		`1.5`:                  {},
	}
	invalid := map[string]bool{`"  "`: true, `[1, 2]`: true, `"1-2-3"`: true, `"a-b"`: true, `"2147483648"`: true,
		`{"from": 1, "x": 2}`: true, `true`: true, `1.5`: true}
	for input, expected := range valid {
		var value V2RayXHTTPRange
		err := json.Unmarshal([]byte(input), &value)
		if invalid[input] {
			require.Error(t, err, input)
			continue
		}
		require.NoError(t, err, input)
		require.Equal(t, expected, value, input)
		output, err := json.Marshal(value)
		require.NoError(t, err)
		var again V2RayXHTTPRange
		require.NoError(t, json.Unmarshal(output, &again))
		require.Equal(t, value, again, string(output))
	}
}

func TestV2RayXHTTPTransportOptions(t *testing.T) {
	var options V2RayTransportOptions
	require.NoError(t, json.Unmarshal([]byte(`{
		"type": "xhttp",
		"mode": "packet-up",
		"host": "example.com",
		"path": "/p?ed=2048",
		"headers": {"User-Agent": "firefox"},
		"x_padding_bytes": "100-1000",
		"x_padding_obfs_mode": true,
		"x_padding_placement": "header",
		"session_placement": "header",
		"session_key": "X-Token",
		"session_id_table": "hex",
		"session_id_length": "16-24",
		"sc_max_each_post_bytes": 500000,
		"sc_min_posts_interval_ms": "10-50",
		"no_grpc_header": true,
		"no_sse_header": true,
		"sc_max_buffered_posts": 30,
		"sc_stream_up_server_secs": "20-80",
		"server_max_header_bytes": 8192,
		"xmux": {"max_connections": "2-4", "h_max_request_times": "600-900", "h_keep_alive_period": 30},
		"download": {
			"server": "203.0.113.1",
			"server_port": 443,
			"tls": {"enabled": true, "server_name": "cdn.example.com"},
			"detour": "direct",
			"path": "/d",
			"xmux": {"max_concurrency": "16-32"}
		}
	}`), &options))
	require.Equal(t, C.V2RayTransportTypeXHTTP, options.Type)
	xhttp := options.XHTTPOptions
	require.Equal(t, "packet-up", xhttp.Mode)
	require.Equal(t, V2RayXHTTPRange{100, 1000}, *xhttp.XPaddingBytes)
	require.Equal(t, V2RayXHTTPRange{500000, 500000}, *xhttp.ScMaxEachPostBytes)
	require.Equal(t, int64(30), xhttp.Xmux.HKeepAlivePeriod)
	require.Equal(t, "203.0.113.1", xhttp.Download.Server)
	require.Equal(t, "cdn.example.com", xhttp.Download.TLS.ServerName)
	require.Equal(t, "/d", xhttp.Download.Path)
	require.Equal(t, V2RayXHTTPRange{16, 32}, *xhttp.Download.Xmux.MaxConcurrency)

	output, err := json.Marshal(options)
	require.NoError(t, err)
	var again V2RayTransportOptions
	require.NoError(t, json.Unmarshal(output, &again))
	require.Equal(t, options, again)
}

// Unknown fields are errors, as everywhere in sing-box: the fields only
// sing-box-extended has and the names only sing-box-lx uses among them.
func TestV2RayXHTTPUnknownFields(t *testing.T) {
	for _, input := range []string{
		`{"type": "xhttp", "domain_strategy": "ipv4_only"}`,
		`{"type": "xhttp", "trusted_x_forwarded_for": ["1.1.1.1"]}`,
		`{"type": "xhttp", "congestion_controller": "bbr"}`,
		`{"type": "xhttp", "cwnd": 10}`,
		`{"type": "xhttp", "session_table": "hex"}`,
		`{"type": "xhttp", "extra": {"xPaddingBytes": "100-1000"}}`,
		`{"type": "xhttp", "xPaddingBytes": "100-1000"}`,
		`{"type": "xhttp", "xmux": {"maxConnections": 3}}`,
		`{"type": "xhttp", "download": {"server": "a", "server_port": 1, "address": "b"}}`,
	} {
		var options V2RayTransportOptions
		require.Error(t, json.Unmarshal([]byte(input), &options), input)
	}
}

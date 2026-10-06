package main

import (
	"bytes"
	"strings"
	"testing"

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
		"unsupported":         {"", []string{"vless://u@example.org:443?type=kcp"}, "error: unsupported transport: kcp\n"},
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

// Scripts read the features as whole names between commas.
func TestVersionFeatures(t *testing.T) {
	seen := make(map[string]bool)
	for _, feature := range versionFeatures {
		require.NotContains(t, feature, ",")
		require.NotContains(t, feature, " ")
		require.False(t, seen[feature], feature)
		seen[feature] = true
	}
	require.True(t, seen["tools.decode-link"])
}

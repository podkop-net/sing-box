package rule

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"github.com/stretchr/testify/require"
)

// A rule set closed while it reads a downloaded list stops reading it: the content it had
// stays, and the error is the one of its context.
func TestRemoteRuleSetClosedStopsReading(t *testing.T) {
	var source, text strings.Builder
	source.WriteString(`{"version":3,"rules":[{"domain_suffix":[`)
	for index := range 50000 {
		if index > 0 {
			source.WriteByte(',')
		}
		fmt.Fprintf(&source, `"host%d.example.com"`, index)
		fmt.Fprintf(&text, "host%d.example.com\n", index)
	}
	source.WriteString(`]}]}`)
	for format, content := range map[string]string{C.RuleSetFormatSource: source.String(), C.RuleSetFormatText: text.String()} {
		ctx, cancel := context.WithCancel(context.Background())
		ruleSet := &RemoteRuleSet{ctx: ctx, tag: "big", options: option.RuleSet{Format: format}}
		cancel()
		require.ErrorIs(t, ruleSet.commitBytes([]byte(content)), context.Canceled, format)
		require.Nil(t, ruleSet.rules, format)
	}
}

func TestContextReader(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	reader := contextReader{ctx, bytes.NewReader([]byte("abcdef"))}
	buffer := make([]byte, 3)
	count, err := reader.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, 3, count)
	cancel()
	_, err = reader.Read(buffer)
	require.ErrorIs(t, err, context.Canceled)
}

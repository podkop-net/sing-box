package domainset

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// bigSource is a rule set of the source format with count names in one rule.
func bigSource(count int) []byte {
	var text strings.Builder
	text.WriteString(`{"version":3,"rules":[{"domain_suffix":[`)
	for index := range count {
		if index > 0 {
			text.WriteByte(',')
		}
		fmt.Fprintf(&text, `"host%d.example%d.com"`, index, index%97)
	}
	text.WriteString(`]}]}`)
	return []byte(text.String())
}

// A rule set read for a context that is done stops with its error, and is not read by
// sing-box instead; one read for a live context is read as before.
func TestReadSourceContextStops(t *testing.T) {
	text := bigSource(50000)
	done, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ReadSourceContext(done, text)
	require.ErrorIs(t, err, context.Canceled)
	compat, err := ReadSourceContext(context.Background(), text)
	require.NoError(t, err)
	require.NotNil(t, compat.Options.Rules[0].DefaultOptions.DomainSet)
}

// The build of the trie stops too: the names are gathered, the context ends, the set is
// not made.
func TestCollectorContextStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	names := NewCollectorContext(ctx, nil)
	for index := range 50000 {
		require.NoError(t, names.AddString(fmt.Sprintf("host%d.example.com", index), true))
	}
	cancel()
	_, err := names.Set("")
	require.ErrorIs(t, err, context.Canceled)
	_, err = NewCollectorContext(context.Background(), nil).Set("")
	require.Error(t, err, "no domain to build")
}

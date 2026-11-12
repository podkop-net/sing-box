package ruletext

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// A text list read for a context that is done stops with its error.
func TestReadContextStops(t *testing.T) {
	var text strings.Builder
	for index := range 50000 {
		fmt.Fprintf(&text, "host%d.example.com\n", index)
	}
	done, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := ReadContext(done, []byte(text.String()))
	require.ErrorIs(t, err, context.Canceled)
	compat, _, err := ReadContext(context.Background(), []byte(text.String()))
	require.NoError(t, err)
	require.Len(t, compat.Options.Rules, 1)
}

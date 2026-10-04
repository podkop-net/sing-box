package log

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Entries go to the observer while someone reads them (the Clash API's /logs), all levels
// included; before and after, nothing is formatted for it.
func TestObservableOnlyWhileSubscribed(t *testing.T) {
	factory := NewDefaultFactory(context.Background(), Formatter{BaseTime: time.Now()}, consoleWriter{}, "", nil, true)
	factory.SetLevel(LevelWarn)
	require.NoError(t, factory.Start())
	defer factory.Close()
	internal := factory.(*defaultFactory)
	logger := factory.NewLogger("dns")
	require.False(t, internal.observed())

	subscription, _, err := factory.Subscribe()
	require.NoError(t, err)
	require.True(t, internal.observed())
	logger.Debug("below the level")
	select {
	case entry := <-subscription:
		require.Equal(t, LevelDebug, entry.Level)
		require.Contains(t, entry.Message, "below the level")
	case <-time.After(2 * time.Second):
		t.Fatal("the subscription got no entry")
	}

	factory.UnSubscribe(subscription)
	require.False(t, internal.observed())
}

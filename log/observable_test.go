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

// recordingWriter keeps what a platform writer is given.
type recordingWriter struct {
	level    Level
	messages *[]string
}

func (w recordingWriter) WriteMessage(level Level, message string) {
	*w.messages = append(*w.messages, FormatLevel(level)+" "+message)
}

type leveledRecordingWriter struct{ recordingWriter }

func (w leveledRecordingWriter) Level() Level      { return w.level }
func (leveledRecordingWriter) DisableColors() bool { return true }

// A platform writer with a level is given the entries of its level and below, without
// colours; one without a level is given every entry, whatever the level of the log.
func TestPlatformWriterLevel(t *testing.T) {
	var leveled, every []string
	factory := NewDefaultFactory(context.Background(), Formatter{BaseTime: time.Now()}, consoleWriter{}, "", leveledRecordingWriter{recordingWriter{level: LevelWarn, messages: &leveled}}, false)
	factory.SetLevel(LevelError)
	require.NoError(t, factory.Start())
	defer factory.Close()
	logger := factory.NewLogger("dns")
	logger.Debug("debug line")
	logger.Warn("warn line")
	require.Len(t, leveled, 1)
	require.Contains(t, leveled[0], "warn line")
	require.NotContains(t, leveled[0], "\x1b[")

	factory.AttachPlatformWriter(recordingWriter{messages: &every})
	logger.Debug("second debug line")
	logger.Warn("second warn line")
	require.Len(t, leveled, 2)
	require.Len(t, every, 2)
	require.Contains(t, every[0], "second debug line")
	require.Contains(t, every[1], "\x1b[", "a writer that does not ask otherwise gets the colours")
}

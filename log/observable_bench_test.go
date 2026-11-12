package log

import (
	"context"
	"testing"
	"time"
)

// consoleWriter stands for the console sing-box writes to: anything but io.Discard.
type consoleWriter struct{}

func (consoleWriter) Write(p []byte) (int, error) { return len(p), nil }

// platformWriter stands for the writer of an app or of a program that embeds sing-box:
// one that takes every level, and one with a level of its own that wants no colours.
type platformWriter struct{}

func (platformWriter) WriteMessage(level Level, message string) {}

type leveledPlatformWriter struct{ level Level }

func (leveledPlatformWriter) WriteMessage(level Level, message string) {}
func (w leveledPlatformWriter) Level() Level                           { return w.level }
func (leveledPlatformWriter) DisableColors() bool                      { return true }

// A debug line below the warn level, as the router and DNS write for every connection and
// query, with the Clash API on (observable) or off.
func BenchmarkLogBelowLevel(b *testing.B) {
	for _, testCase := range []struct {
		name       string
		observable bool
		subscribe  bool
		platform   PlatformWriter
	}{
		{"clash api off", false, false, nil},
		{"clash api on", true, false, nil},
		{"clash api on, logs subscribed", true, true, nil},
		{"platform writer without a level", false, false, platformWriter{}},
		{"platform writer at warn", false, false, leveledPlatformWriter{LevelWarn}},
	} {
		b.Run(testCase.name, func(b *testing.B) {
			factory := NewDefaultFactory(context.Background(), Formatter{BaseTime: time.Now()}, consoleWriter{}, "", testCase.platform, testCase.observable)
			factory.SetLevel(LevelWarn)
			if err := factory.Start(); err != nil {
				b.Fatal(err)
			}
			defer factory.Close()
			if testCase.subscribe {
				subscription, _, err := factory.Subscribe()
				if err != nil {
					b.Fatal(err)
				}
				defer factory.UnSubscribe(subscription)
				go func() {
					for range subscription {
					}
				}()
			}
			logger := factory.NewLogger("dns")
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				logger.DebugContext(ctx, "exchanged ", "www.example.com", " IN A ", 1234, " in ", 12, "ms")
			}
		})
	}
}

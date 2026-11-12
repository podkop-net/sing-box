package log

import (
	"context"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service/filemanager"
)

var _ ObservableFactory = (*defaultFactory)(nil)

type defaultFactory struct {
	ctx               context.Context
	formatter         Formatter
	platformFormatter Formatter
	writer            io.Writer
	file              *os.File
	filePath          string
	platformWriters   atomic.Pointer[[]PlatformWriter]
	needConsole       bool
	needObservable    bool
	subscriptions     atomic.Int32 // entries are formatted for the observer only while it has some
	level             Level
	subscriber        *observable.Subscriber[Entry]
	observer          *observable.Observer[Entry]
	startAccess       sync.Mutex
	started           atomic.Bool
	pendingEntries    []pendingEntry
}

type pendingEntry struct {
	ctx       context.Context
	level     Level
	tag       string
	message   string
	timestamp time.Time
}

func NewDefaultFactory(
	ctx context.Context,
	formatter Formatter,
	writer io.Writer,
	filePath string,
	platformWriter PlatformWriter,
	needObservable bool,
) ObservableFactory {
	factory := &defaultFactory{
		ctx:       ctx,
		formatter: formatter,
		platformFormatter: Formatter{
			BaseTime:         formatter.BaseTime,
			DisableLineBreak: true,
		},
		writer:         writer,
		filePath:       filePath,
		needConsole:    writer != io.Discard || filePath != "",
		needObservable: needObservable,
		level:          LevelTrace,
		subscriber:     observable.NewSubscriber[Entry](128),
	}
	if platformWriter != nil {
		factory.platformWriters.Store(&[]PlatformWriter{platformWriter})
	}
	/*if platformWriter != nil {
		factory.platformFormatter.DisableColors = platformWriter.DisableColors()
	}*/
	return factory
}

func (f *defaultFactory) Start() error {
	var err error
	if f.filePath != "" {
		logFile, openErr := filemanager.OpenFile(f.ctx, f.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if openErr != nil {
			err = openErr
		} else {
			f.writer = logFile
			f.file = logFile
		}
		f.needConsole = f.writer != io.Discard
	}
	if f.needObservable {
		f.observer = observable.NewObserver[Entry](f.subscriber, 64)
	}
	f.startAccess.Lock()
	pendingEntries := f.pendingEntries
	f.pendingEntries = nil
	f.started.Store(true)
	f.startAccess.Unlock()
	for _, entry := range pendingEntries {
		f.output(entry.ctx, entry.level, entry.tag, entry.message, entry.timestamp)
	}
	return err
}

func (f *defaultFactory) Close() error {
	f.startAccess.Lock()
	f.pendingEntries = nil
	f.startAccess.Unlock()
	return common.Close(
		common.PtrOrNil(f.file),
		f.subscriber,
	)
}

func (f *defaultFactory) AttachPlatformWriter(writer PlatformWriter) {
	writers := append(f.loadPlatformWriters(), writer)
	f.platformWriters.Store(&writers)
}

func (f *defaultFactory) loadPlatformWriters() []PlatformWriter {
	writers := f.platformWriters.Load()
	if writers == nil {
		return nil
	}
	return *writers
}

func (f *defaultFactory) Level() Level {
	return f.level
}

func (f *defaultFactory) SetLevel(level Level) {
	f.level = level
}

func (f *defaultFactory) Logger() ContextLogger {
	return f.NewLogger("")
}

func (f *defaultFactory) NewLogger(tag string) ContextLogger {
	return &observableLogger{f, tag}
}

func (f *defaultFactory) Subscribe() (subscription observable.Subscription[Entry], done <-chan struct{}, err error) {
	subscription, done, err = f.observer.Subscribe()
	if err == nil {
		f.subscriptions.Add(1)
	}
	return
}

func (f *defaultFactory) UnSubscribe(sub observable.Subscription[Entry]) {
	f.subscriptions.Add(-1)
	f.observer.UnSubscribe(sub)
}

// observed reports whether an entry goes to the observer: with the Clash API on, and only
// while someone reads its logs. Formatting every entry below the level for nobody cost each
// log call of the router and DNS some ten times the call itself.
func (f *defaultFactory) observed() bool {
	return f.needObservable && f.subscriptions.Load() > 0
}

func (f *defaultFactory) output(ctx context.Context, level Level, tag string, message string, timestamp time.Time) {
	if level <= f.level && (f.needConsole || level == LevelPanic || level == LevelFatal) {
		formatted := f.formatter.Format(ctx, level, tag, message, timestamp)
		if level == LevelPanic {
			panic(formatted)
		}
		f.writer.Write([]byte(formatted))
		if level == LevelFatal {
			os.Exit(1)
		}
	}
	if f.observed() {
		f.subscriber.Emit(Entry{level, f.formatter.FormatSimple(ctx, tag, message)})
	}
	// formatted once for the writers that want colours and once for those that do not,
	// and only when one of them takes the level
	var coloured, plain string
	for _, platformWriter := range f.loadPlatformWriters() {
		if !platformTakes(platformWriter, level) {
			continue
		}
		if platformPlain(platformWriter) {
			if plain == "" {
				formatter := f.platformFormatter
				formatter.DisableColors = true
				plain = formatter.Format(ctx, level, tag, message, timestamp)
			}
			platformWriter.WriteMessage(level, plain)
		} else {
			if coloured == "" {
				coloured = f.platformFormatter.Format(ctx, level, tag, message, timestamp)
			}
			platformWriter.WriteMessage(level, coloured)
		}
	}
}

// platformWants tells whether a platform writer takes an entry of the level.
func (f *defaultFactory) platformWants(level Level) bool {
	for _, platformWriter := range f.loadPlatformWriters() {
		if platformTakes(platformWriter, level) {
			return true
		}
	}
	return false
}

var _ ContextLogger = (*observableLogger)(nil)

type observableLogger struct {
	*defaultFactory
	tag string
}

func (l *observableLogger) Log(ctx context.Context, level Level, args []any) {
	level = OverrideLevelFromContext(level, ctx)
	if level > l.level && !l.platformWants(level) && !l.observed() {
		return
	}
	nowTime := time.Now()
	message := F.ToString(args...)
	if !l.started.Load() && level != LevelFatal && level != LevelPanic {
		l.startAccess.Lock()
		if !l.started.Load() {
			l.pendingEntries = append(l.pendingEntries, pendingEntry{ctx, level, l.tag, message, nowTime})
			l.startAccess.Unlock()
			return
		}
		l.startAccess.Unlock()
	}
	l.output(ctx, level, l.tag, message, nowTime)
}

func (l *observableLogger) Trace(args ...any) {
	l.TraceContext(context.Background(), args...)
}

func (l *observableLogger) Debug(args ...any) {
	l.DebugContext(context.Background(), args...)
}

func (l *observableLogger) Info(args ...any) {
	l.InfoContext(context.Background(), args...)
}

func (l *observableLogger) Warn(args ...any) {
	l.WarnContext(context.Background(), args...)
}

func (l *observableLogger) Error(args ...any) {
	l.ErrorContext(context.Background(), args...)
}

func (l *observableLogger) Fatal(args ...any) {
	l.FatalContext(context.Background(), args...)
}

func (l *observableLogger) Panic(args ...any) {
	l.PanicContext(context.Background(), args...)
}

func (l *observableLogger) TraceContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelTrace, args)
}

func (l *observableLogger) DebugContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelDebug, args)
}

func (l *observableLogger) InfoContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelInfo, args)
}

func (l *observableLogger) WarnContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelWarn, args)
}

func (l *observableLogger) ErrorContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelError, args)
}

func (l *observableLogger) FatalContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelFatal, args)
}

func (l *observableLogger) PanicContext(ctx context.Context, args ...any) {
	l.Log(ctx, LevelPanic, args)
}

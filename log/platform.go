package log

type PlatformWriter interface {
	WriteMessage(level Level, message string)
}

// PlatformWriterLevel is a PlatformWriter that takes the entries of its level and below
// only: an entry above it is not formatted for it. A writer without a level takes every
// entry, whatever the level of the log.
type PlatformWriterLevel interface {
	PlatformWriter
	Level() Level
}

// PlatformWriterColors is a PlatformWriter that may ask for its messages without the
// colours of a terminal.
type PlatformWriterColors interface {
	PlatformWriter
	DisableColors() bool
}

// platformTakes tells whether a platform writer takes an entry of the level.
func platformTakes(writer PlatformWriter, level Level) bool {
	leveled, hasLevel := writer.(PlatformWriterLevel)
	return !hasLevel || level <= leveled.Level()
}

func platformPlain(writer PlatformWriter) bool {
	colors, hasColors := writer.(PlatformWriterColors)
	return hasColors && colors.DisableColors()
}

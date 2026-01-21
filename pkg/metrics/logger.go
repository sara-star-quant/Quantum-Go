package metrics

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Level represents a logging level.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelSilent // Disables all logging
)

// String returns the level name.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelSilent:
		return "SILENT"
	default:
		return "UNKNOWN"
	}
}

// ParseLevel parses a level string.
func ParseLevel(s string) Level {
	switch strings.ToUpper(s) {
	case "DEBUG":
		return LevelDebug
	case "INFO":
		return LevelInfo
	case "WARN", "WARNING":
		return LevelWarn
	case "ERROR":
		return LevelError
	case "SILENT", "OFF", "NONE":
		return LevelSilent
	default:
		return LevelInfo
	}
}

// Logger provides structured logging with levels.
type Logger struct {
	mu       sync.Mutex
	out      io.Writer
	level    Level
	format   Format
	fields   Fields
	name     string
	timeFunc func() time.Time
}

// Fields represents structured log fields.
type Fields map[string]interface{}

// Format specifies the log output format.
type Format int

const (
	FormatText Format = iota // Human-readable text format
	FormatJSON               // JSON format for log aggregation
)

// LoggerOption configures a logger.
type LoggerOption func(*Logger)

// WithOutput sets the output writer.
func WithOutput(w io.Writer) LoggerOption {
	return func(l *Logger) {
		l.out = w
	}
}

// WithLevel sets the minimum log level.
func WithLevel(level Level) LoggerOption {
	return func(l *Logger) {
		l.level = level
	}
}

// WithFormat sets the output format.
func WithFormat(format Format) LoggerOption {
	return func(l *Logger) {
		l.format = format
	}
}

// WithFields sets default fields for all log entries.
func WithFields(fields Fields) LoggerOption {
	return func(l *Logger) {
		l.fields = fields
	}
}

// WithName sets the logger name.
func WithName(name string) LoggerOption {
	return func(l *Logger) {
		l.name = name
	}
}

// NewLogger creates a new logger with the given options.
func NewLogger(opts ...LoggerOption) *Logger {
	l := &Logger{
		out:      os.Stdout,
		level:    LevelInfo,
		format:   FormatText,
		fields:   make(Fields),
		timeFunc: time.Now,
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// With returns a new logger with additional fields.
func (l *Logger) With(fields Fields) *Logger {
	newFields := make(Fields, len(l.fields)+len(fields))
	for k, v := range l.fields {
		newFields[k] = v
	}
	for k, v := range fields {
		newFields[k] = v
	}
	return &Logger{
		out:      l.out,
		level:    l.level,
		format:   l.format,
		fields:   newFields,
		name:     l.name,
		timeFunc: l.timeFunc,
	}
}

// Named returns a new logger with the given name.
func (l *Logger) Named(name string) *Logger {
	newName := name
	if l.name != "" {
		newName = l.name + "." + name
	}
	return &Logger{
		out:      l.out,
		level:    l.level,
		format:   l.format,
		fields:   l.fields,
		name:     newName,
		timeFunc: l.timeFunc,
	}
}

// SetLevel changes the logging level.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// Debug logs at debug level.
func (l *Logger) Debug(msg string, fields ...Fields) {
	l.log(LevelDebug, msg, fields...)
}

// Info logs at info level.
func (l *Logger) Info(msg string, fields ...Fields) {
	l.log(LevelInfo, msg, fields...)
}

// Warn logs at warn level.
func (l *Logger) Warn(msg string, fields ...Fields) {
	l.log(LevelWarn, msg, fields...)
}

// Error logs at error level.
func (l *Logger) Error(msg string, fields ...Fields) {
	l.log(LevelError, msg, fields...)
}

// log performs the actual logging.
func (l *Logger) log(level Level, msg string, extraFields ...Fields) {
	if level < l.level {
		return
	}

	// Merge fields
	allFields := make(Fields, len(l.fields))
	for k, v := range l.fields {
		allFields[k] = v
	}
	for _, f := range extraFields {
		for k, v := range f {
			allFields[k] = v
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.format == FormatJSON {
		l.writeJSON(level, msg, allFields)
	} else {
		l.writeText(level, msg, allFields)
	}
}

// writeJSON writes a log entry in JSON format.
func (l *Logger) writeJSON(level Level, msg string, fields Fields) {
	entry := make(map[string]interface{}, len(fields)+4)
	entry["time"] = l.timeFunc().Format(time.RFC3339Nano)
	entry["level"] = level.String()
	entry["msg"] = msg
	if l.name != "" {
		entry["logger"] = l.name
	}
	for k, v := range fields {
		entry[k] = v
	}

	data, err := json.Marshal(entry)
	if err != nil {
		// Fallback to text
		fmt.Fprintf(l.out, "LOG_ERROR: %v\n", err)
		return
	}
	l.out.Write(data)
	l.out.Write([]byte{'\n'})
}

// writeText writes a log entry in human-readable text format.
func (l *Logger) writeText(level Level, msg string, fields Fields) {
	var b strings.Builder

	// Timestamp
	b.WriteString(l.timeFunc().Format("15:04:05.000"))
	b.WriteString(" ")

	// Level with color codes (if supported)
	b.WriteString(levelColor(level))
	b.WriteString(fmt.Sprintf("%-5s", level.String()))
	b.WriteString(colorReset)
	b.WriteString(" ")

	// Logger name
	if l.name != "" {
		b.WriteString("[")
		b.WriteString(l.name)
		b.WriteString("] ")
	}

	// Message
	b.WriteString(msg)

	// Fields
	if len(fields) > 0 {
		b.WriteString(" ")
		b.WriteString(formatFields(fields))
	}

	b.WriteString("\n")
	l.out.Write([]byte(b.String()))
}

// formatFields formats fields as key=value pairs.
func formatFields(fields Fields) string {
	if len(fields) == 0 {
		return ""
	}

	// Sort keys for consistent output
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := fields[k]
		parts = append(parts, fmt.Sprintf("%s=%v", k, v))
	}

	return strings.Join(parts, " ")
}

// ANSI color codes for log levels.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorGray   = "\033[90m"
)

func levelColor(level Level) string {
	switch level {
	case LevelDebug:
		return colorGray
	case LevelInfo:
		return colorBlue
	case LevelWarn:
		return colorYellow
	case LevelError:
		return colorRed
	default:
		return ""
	}
}

// --- Global Logger ---

var (
	globalLogger   *Logger
	globalLoggerMu sync.RWMutex
)

func init() {
	globalLogger = NewLogger()
}

// SetLogger sets the global logger.
func SetLogger(l *Logger) {
	globalLoggerMu.Lock()
	defer globalLoggerMu.Unlock()
	globalLogger = l
}

// GetLogger returns the global logger.
func GetLogger() *Logger {
	globalLoggerMu.RLock()
	defer globalLoggerMu.RUnlock()
	return globalLogger
}

// Log functions using the global logger.

// Debug logs at debug level using the global logger.
func Debug(msg string, fields ...Fields) {
	GetLogger().Debug(msg, fields...)
}

// Info logs at info level using the global logger.
func Info(msg string, fields ...Fields) {
	GetLogger().Info(msg, fields...)
}

// Warn logs at warn level using the global logger.
func Warn(msg string, fields ...Fields) {
	GetLogger().Warn(msg, fields...)
}

// Error logs at error level using the global logger.
func Error(msg string, fields ...Fields) {
	GetLogger().Error(msg, fields...)
}

// --- Convenience Functions ---

// NullLogger returns a logger that discards all output.
func NullLogger() *Logger {
	return NewLogger(WithLevel(LevelSilent))
}

// TestLogger returns a logger suitable for testing (debug level, text format).
func TestLogger(w io.Writer) *Logger {
	return NewLogger(
		WithOutput(w),
		WithLevel(LevelDebug),
		WithFormat(FormatText),
	)
}

// ProductionLogger returns a logger suitable for production (info level, JSON format).
func ProductionLogger(w io.Writer) *Logger {
	return NewLogger(
		WithOutput(w),
		WithLevel(LevelInfo),
		WithFormat(FormatJSON),
	)
}

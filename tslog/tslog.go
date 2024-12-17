// Package tslog provides a tinted structured logging implementation.
package tslog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/database64128/swgp-go/conn"
	"github.com/lmittmann/tint"
)

// Config is a set of options for a [*Logger].
type Config struct {
	// Level is the minimum level of log messages to write.
	Level slog.Level `json:"level"`

	// NoColor disables color in log messages.
	NoColor bool `json:"no_color"`

	// NoTime disables timestamps in log messages.
	NoTime bool `json:"no_time"`

	// UseTextHandler enables the use of a [*slog.TextHandler] instead of the default tint handler.
	UseTextHandler bool `json:"use_text_handler"`

	// UseJSONHandler enables the use of a [*slog.JSONHandler] instead of the default tint handler.
	UseJSONHandler bool `json:"use_json_handler"`
}

// NewLogger creates a new [*Logger] that writes to w.
func (c *Config) NewLogger(w io.Writer) *Logger {
	return &Logger{
		level:   c.Level,
		noTime:  c.NoTime,
		handler: c.newHandler(w),
	}
}

func (c *Config) newHandler(w io.Writer) slog.Handler {
	if c.UseTextHandler {
		return slog.NewTextHandler(w, &slog.HandlerOptions{
			Level: c.Level,
		})
	}
	if c.UseJSONHandler {
		return slog.NewJSONHandler(w, &slog.HandlerOptions{
			Level: c.Level,
		})
	}
	return tint.NewHandler(w, &tint.Options{
		Level:   c.Level,
		NoColor: c.NoColor,
	})
}

// NewLoggerWithHandler creates a new [*Logger] with the given handler.
func (c *Config) NewLoggerWithHandler(handler slog.Handler) *Logger {
	return &Logger{
		level:   c.Level,
		noTime:  c.NoTime,
		handler: handler,
	}
}

// NewTestLogger creates a new [*Logger] for use in tests.
func (c *Config) NewTestLogger(t testingLogger) *Logger {
	return &Logger{
		level:   c.Level,
		noTime:  c.NoTime,
		handler: c.newHandler(newTestingWriter(t)),
	}
}

// Logger is an opinionated logging implementation that writes structured log messages,
// tinted with color by default, to its handler.
type Logger struct {
	level   slog.Level
	noTime  bool
	handler slog.Handler
}

// Handler returns the logger's handler.
func (l *Logger) Handler() slog.Handler {
	return l.handler
}

// WithAttrs returns a new [*Logger] with the given attributes included in every log message.
func (l *Logger) WithAttrs(attrs ...slog.Attr) *Logger {
	return &Logger{
		level:   l.level,
		noTime:  l.noTime,
		handler: l.handler.WithAttrs(attrs),
	}
}

// WithGroup returns a new [*Logger] that scopes all log messages under the given group.
func (l *Logger) WithGroup(group string) *Logger {
	return &Logger{
		level:   l.level,
		noTime:  l.noTime,
		handler: l.handler.WithGroup(group),
	}
}

// Debug logs the given message at [slog.LevelDebug].
func (l *Logger) Debug(msg string, attrs ...slog.Attr) {
	l.Log(slog.LevelDebug, msg, attrs...)
}

// Info logs the given message at [slog.LevelInfo].
func (l *Logger) Info(msg string, attrs ...slog.Attr) {
	l.Log(slog.LevelInfo, msg, attrs...)
}

// Warn logs the given message at [slog.LevelWarn].
func (l *Logger) Warn(msg string, attrs ...slog.Attr) {
	l.Log(slog.LevelWarn, msg, attrs...)
}

// Error logs the given message at [slog.LevelError].
func (l *Logger) Error(msg string, attrs ...slog.Attr) {
	l.Log(slog.LevelError, msg, attrs...)
}

// Enabled returns whether logging at the given level is enabled.
func (l *Logger) Enabled(level slog.Level) bool {
	return level >= l.level
}

// Log logs the given message at the given level.
func (l *Logger) Log(level slog.Level, msg string, attrs ...slog.Attr) {
	if !l.Enabled(level) {
		return
	}
	l.log(level, msg, attrs...)
}

// log implements the actual logging logic, so that its callers (the exported log methods)
// become eligible for mid-stack inlining.
func (l *Logger) log(level slog.Level, msg string, attrs ...slog.Attr) {
	var t time.Time
	if !l.noTime {
		t = time.Now()
	}
	r := slog.NewRecord(t, level, msg, 0)
	r.AddAttrs(attrs...)
	if err := l.handler.Handle(context.Background(), r); err != nil {
		fmt.Fprintf(os.Stderr, "tslog: failed to write log message: %v\n", err)
	}
}

// Err is a convenience wrapper for [tint.Err].
func Err(err error) slog.Attr {
	return tint.Err(err)
}

// Int returns a [slog.Attr] for a signed integer of any size.
func Int[V ~int | ~int8 | ~int16 | ~int32 | ~int64](key string, value V) slog.Attr {
	return slog.Int64(key, int64(value))
}

// Uint returns a [slog.Attr] for an unsigned integer of any size.
func Uint[V ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr](key string, value V) slog.Attr {
	return slog.Uint64(key, uint64(value))
}

// Addr returns a [slog.Attr] for a [netip.Addr].
//
// If addr is the zero value, the value is the empty string.
func Addr(key string, addr netip.Addr) slog.Attr {
	var s string
	if addr.IsValid() {
		s = addr.String()
	}
	return slog.String(key, s)
}

// AddrPort returns a [slog.Attr] for a [netip.AddrPort].
//
// If addrPort is the zero value, the value is the empty string.
func AddrPort(key string, addrPort netip.AddrPort) slog.Attr {
	var s string
	if addrPort.IsValid() {
		s = addrPort.String()
	}
	return slog.String(key, s)
}

// ConnAddr returns a [slog.Attr] for a [conn.Addr].
func ConnAddr(key string, addr conn.Addr) slog.Attr {
	return slog.String(key, addr.String())
}

// Addrp returns a [slog.Attr] for a [*netip.Addr].
//
// Use [Addr] if the address is not already on the heap,
// or the call is guarded by [Logger.Enabled].
func Addrp(key string, addrp *netip.Addr) slog.Attr {
	return slog.Any(key, addrp)
}

// AddrPortp returns a [slog.Attr] for a [*netip.AddrPort].
//
// Use [AddrPort] if the address is not already on the heap,
// or the call is guarded by [Logger.Enabled].
func AddrPortp(key string, addrPortp *netip.AddrPort) slog.Attr {
	return slog.Any(key, addrPortp)
}

// ConnAddrp returns a [slog.Attr] for a [*conn.Addr].
//
// Use [ConnAddr] if the address is not already on the heap,
// or the call is guarded by [Logger.Enabled].
func ConnAddrp(key string, addrp *conn.Addr) slog.Attr {
	return slog.Any(key, addrp)
}

type testingLogger interface {
	Logf(format string, args ...any)
}

type testingWriter struct {
	t testingLogger
}

func newTestingWriter(t testingLogger) *testingWriter {
	return &testingWriter{t}
}

func (w *testingWriter) Write(p []byte) (n int, err error) {
	w.t.Logf("%s", p)
	return len(p), nil
}

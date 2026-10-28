// Package tslog provides a tinted structured logging implementation.
package tslog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"runtime"
	"time"
	"unsafe"

	"github.com/database64128/swgp-go/conn"
	"github.com/lmittmann/tint"
)

// Format represents the log format, which usually corresponds to a specific [slog.Handler] implementation.
type Format uint8

const (
	// FormatDefault specifies the default log format, which is currently [FormatTintText].
	FormatDefault Format = iota

	// FormatSlogText uses [*slog.TextHandler].
	FormatSlogText

	// FormatSlogJSON uses [*slog.JSONHandler].
	FormatSlogJSON

	// FormatTintText uses [tint]'s text handler, which uses its custom text format with color.
	FormatTintText

	// FormatTintJSON uses [tint]'s JSON handler, which pretty-prints JSON log messages with color.
	// Will be available in a future tint release.
)

const (
	formatDefaultString  = "default"
	formatSlogTextString = "slog-text"
	formatSlogJSONString = "slog-json"
	formatTintTextString = "tint-text"
	// formatTintJSONString = "tint-json"
)

// AppendText implements [encoding.TextAppender].
func (f Format) AppendText(b []byte) ([]byte, error) {
	switch f {
	case FormatDefault:
		return append(b, formatDefaultString...), nil
	case FormatSlogText:
		return append(b, formatSlogTextString...), nil
	case FormatSlogJSON:
		return append(b, formatSlogJSONString...), nil
	case FormatTintText:
		return append(b, formatTintTextString...), nil
	default:
		return b, fmt.Errorf("invalid format: %d", f)
	}
}

// MarshalText implements [encoding.TextMarshaler].
func (f Format) MarshalText() ([]byte, error) {
	return f.AppendText(nil)
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (f *Format) UnmarshalText(text []byte) error {
	switch string(text) {
	case formatDefaultString, "":
		*f = FormatDefault
	case formatSlogTextString:
		*f = FormatSlogText
	case formatSlogJSONString:
		*f = FormatSlogJSON
	case formatTintTextString:
		*f = FormatTintText
	default:
		return fmt.Errorf("invalid format: %q", text)
	}
	return nil
}

// Config is a set of options for a [*Logger].
type Config struct {
	// Level is the minimum level of log messages to write.
	Level slog.Level `json:"level,omitzero"`

	// Format specifies the log format.
	Format Format `json:"format,omitzero"`

	// NoColor disables color in log messages.
	NoColor bool `json:"noColor,omitzero"`

	// NoTime disables timestamps in log messages.
	NoTime bool `json:"noTime,omitzero"`

	// AddSource enables the inclusion of source file and line number in log messages.
	AddSource bool `json:"addSource,omitzero"`
}

// NewLogger creates a new [*Logger] that writes to w.
func (c Config) NewLogger(w io.Writer) (*Logger, error) {
	handler, err := c.NewHandler(w)
	if err != nil {
		return nil, err
	}
	return c.NewLoggerWithHandler(handler), nil
}

// NewHandler creates a new [slog.Handler] that writes to w.
func (c Config) NewHandler(w io.Writer) (slog.Handler, error) {
	switch c.Format {
	case FormatSlogText:
		return slog.NewTextHandler(w, &slog.HandlerOptions{
			AddSource: c.AddSource,
			Level:     c.Level,
		}), nil
	case FormatSlogJSON:
		return slog.NewJSONHandler(w, &slog.HandlerOptions{
			AddSource: c.AddSource,
			Level:     c.Level,
		}), nil
	case FormatTintText, FormatDefault:
		return tint.NewTextHandler(w, &tint.Options{
			AddSource: c.AddSource,
			Level:     c.Level,
			NoColor:   c.NoColor,
		}), nil
	default:
		return nil, fmt.Errorf("invalid format: %d", c.Format)
	}
}

// NewLoggerWithHandler creates a new [*Logger] with the given handler.
func (c Config) NewLoggerWithHandler(handler slog.Handler) *Logger {
	return &Logger{
		level:     c.Level,
		noTime:    c.NoTime,
		addSource: c.AddSource,
		handler:   handler,
	}
}

// Logger is an opinionated logging implementation that writes structured log messages,
// tinted with color by default, to its handler.
type Logger struct {
	level     slog.Level
	noTime    bool
	addSource bool
	handler   slog.Handler
}

// Handler returns the logger's handler.
func (l *Logger) Handler() slog.Handler {
	return l.handler
}

// WithAttrs returns a new [*Logger] with the given attributes included in every log message.
func (l *Logger) WithAttrs(attrs ...slog.Attr) *Logger {
	return &Logger{
		level:     l.level,
		noTime:    l.noTime,
		addSource: l.addSource,
		handler:   l.handler.WithAttrs(attrs),
	}
}

// WithGroup returns a new [*Logger] that scopes all log messages under the given group.
func (l *Logger) WithGroup(group string) *Logger {
	return &Logger{
		level:     l.level,
		noTime:    l.noTime,
		addSource: l.addSource,
		handler:   l.handler.WithGroup(group),
	}
}

// Debug logs the given message at [slog.LevelDebug].
func (l *Logger) Debug(msg string, attrs ...slog.Attr) {
	if l.Enabled(slog.LevelDebug) {
		l.log(slog.LevelDebug, msg, attrs...)
	}
}

// Info logs the given message at [slog.LevelInfo].
func (l *Logger) Info(msg string, attrs ...slog.Attr) {
	if l.Enabled(slog.LevelInfo) {
		l.log(slog.LevelInfo, msg, attrs...)
	}
}

// Warn logs the given message at [slog.LevelWarn].
func (l *Logger) Warn(msg string, attrs ...slog.Attr) {
	if l.Enabled(slog.LevelWarn) {
		l.log(slog.LevelWarn, msg, attrs...)
	}
}

// Error logs the given message at [slog.LevelError].
func (l *Logger) Error(msg string, attrs ...slog.Attr) {
	if l.Enabled(slog.LevelError) {
		l.log(slog.LevelError, msg, attrs...)
	}
}

// Enabled returns whether logging at the given level is enabled.
func (l *Logger) Enabled(level slog.Level) bool {
	return level >= l.level
}

// Log logs the given message at the given level.
func (l *Logger) Log(level slog.Level, msg string, attrs ...slog.Attr) {
	if l.Enabled(level) {
		l.log(level, msg, attrs...)
	}
}

// log implements the actual logging logic, so that its callers (the exported log methods)
// become eligible for mid-stack inlining.
func (l *Logger) log(level slog.Level, msg string, attrs ...slog.Attr) {
	var t time.Time
	if !l.noTime {
		t = time.Now()
	}

	var pc [1]uintptr
	if l.addSource {
		// skip [runtime.Callers, this function, this function's caller]
		runtime.Callers(3, pc[:])
	}

	r := slog.NewRecord(t, level, msg, pc[0])
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

// ByteString returns a [slog.Attr] for a byte slice as a string value without allocating.
func ByteString(key string, b []byte) slog.Attr {
	return slog.String(key, unsafe.String(unsafe.SliceData(b), len(b)))
}

// Addr returns a [slog.Attr] for a [netip.Addr].
//
// If addr is the zero value, the returned attribute value is the empty string.
func Addr(key string, addr netip.Addr) slog.Attr {
	var s string
	if addr.IsValid() {
		s = addr.String()
	}
	return slog.String(key, s)
}

// AddrPort returns a [slog.Attr] for a [netip.AddrPort].
//
// If addrPort is the zero value, the returned attribute value is the empty string.
func AddrPort(key string, addrPort netip.AddrPort) slog.Attr {
	var s string
	if addrPort.IsValid() {
		s = addrPort.String()
	}
	return slog.String(key, s)
}

// Prefix returns a [slog.Attr] for a [netip.Prefix].
//
// If prefix is the zero value, the returned attribute value is the empty string.
func Prefix(key string, prefix netip.Prefix) slog.Attr {
	var s string
	if prefix.IsValid() {
		s = prefix.String()
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

// Prefixp returns a [slog.Attr] for a [*netip.Prefix].
//
// Use [Prefix] if the prefix is not already on the heap,
// or the call is guarded by [Logger.Enabled].
func Prefixp(key string, prefixp *netip.Prefix) slog.Attr {
	return slog.Any(key, prefixp)
}

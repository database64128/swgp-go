package logging

import (
	"fmt"
	"os"
	"time"

	"github.com/database64128/swgp-go/jsonhelper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NewZapLogger returns a new [*zap.Logger] with the given preset and log level.
//
// The available presets are:
//
//   - "console" (default): Reasonable defaults for production console environments.
//   - "console-nocolor": Same as "console", but without color.
//   - "console-notime": Same as "console", but without timestamps.
//   - "systemd": Reasonable defaults for running as a systemd service. Same as "console", but without color and timestamps.
//   - "production": Zap's built-in production preset.
//   - "development": Zap's built-in development preset.
//
// If the preset is not recognized, it is treated as a path to a JSON configuration file.
//
// The log level does not apply to the "production", "development", or custom presets.
func NewZapLogger(preset string, level zapcore.Level) (*zap.Logger, error) {
	switch preset {
	case "console":
		return NewProductionConsoleZapLogger(level, false, false, false), nil
	case "console-nocolor":
		return NewProductionConsoleZapLogger(level, true, false, false), nil
	case "console-notime":
		return NewProductionConsoleZapLogger(level, false, true, false), nil
	case "systemd":
		return NewProductionConsoleZapLogger(level, true, true, false), nil
	}

	var cfg zap.Config
	switch preset {
	case "production":
		cfg = zap.NewProductionConfig()
	case "development":
		cfg = zap.NewDevelopmentConfig()
	default:
		if err := jsonhelper.OpenAndDecodeDisallowUnknownFields(preset, &cfg); err != nil {
			return nil, fmt.Errorf("failed to load zap logger config from file %q: %w", preset, err)
		}
	}
	return cfg.Build()
}

// NewProductionConsoleZapLogger creates a new [*zap.Logger] with reasonable defaults for production console environments.
//
// See [NewProductionConsoleEncoderConfig] for information on the default encoder configuration.
func NewProductionConsoleZapLogger(level zapcore.Level, noColor, noTime, addCaller bool) *zap.Logger {
	cfg := NewProductionConsoleEncoderConfig(noColor, noTime)
	enc := zapcore.NewConsoleEncoder(cfg)
	core := zapcore.NewCore(enc, zapcore.Lock(os.Stderr), level)
	var opts []zap.Option
	if noTime {
		opts = append(opts, zap.WithClock(fakeClock{})) // Note that the sampler requires a real clock.
	}
	if addCaller {
		opts = append(opts, zap.AddCaller())
	}
	return zap.New(core, opts...)
}

// NewProductionConsoleEncoderConfig returns an opinionated [zapcore.EncoderConfig] for production console environments.
func NewProductionConsoleEncoderConfig(noColor, noTime bool) zapcore.EncoderConfig {
	ec := zapcore.EncoderConfig{
		TimeKey:          "T",
		LevelKey:         "L",
		NameKey:          "N",
		CallerKey:        "C",
		FunctionKey:      zapcore.OmitKey,
		MessageKey:       "M",
		StacktraceKey:    "S",
		LineEnding:       zapcore.DefaultLineEnding,
		EncodeLevel:      zapcore.CapitalColorLevelEncoder,
		EncodeTime:       zapcore.ISO8601TimeEncoder,
		EncodeDuration:   zapcore.StringDurationEncoder,
		EncodeCaller:     zapcore.ShortCallerEncoder,
		ConsoleSeparator: " ",
	}

	if noColor {
		ec.EncodeLevel = zapcore.CapitalLevelEncoder
	}

	if noTime {
		ec.TimeKey = zapcore.OmitKey
		ec.EncodeTime = nil
	}

	return ec
}

// fakeClock is a fake clock that always returns the zero-value time.
//
// fakeClock implements [zapcore.Clock].
type fakeClock struct{}

// Now implements [zapcore.Clock.Now].
func (fakeClock) Now() time.Time {
	return time.Time{}
}

// NewTicker implements [zapcore.Clock.NewTicker].
func (fakeClock) NewTicker(d time.Duration) *time.Ticker {
	return time.NewTicker(d)
}

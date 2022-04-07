package logging

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewProductionConsole(suppressTimestamps bool, logLevel string) (*zap.Logger, error) {
	config, err := NewProductionConsoleConfig(suppressTimestamps, logLevel)
	if err != nil {
		return nil, err
	}
	return config.Build()
}

// NewProductionConsoleConfig is a reasonable production logging configuration.
// Logging is enabled at InfoLevel and above.
//
// It uses a console encoder, writes to standard error, and enables sampling.
// Stacktraces are automatically included on logs of ErrorLevel and above.
func NewProductionConsoleConfig(suppressTimestamps bool, logLevel string) (config zap.Config, err error) {
	var (
		level       zap.AtomicLevel
		development bool
		sampling    *zap.SamplingConfig
	)

	switch logLevel {
	case "", "info", "INFO":
		level = zap.NewAtomicLevelAt(zap.InfoLevel)
	default:
		level, err = zap.ParseAtomicLevel(logLevel)
		if err != nil {
			return
		}
		if level.Level() < zap.InfoLevel {
			// debug level
			development = true
		} else {
			// Enable sampling for non-debugging levels.
			sampling = &zap.SamplingConfig{
				Initial:    100,
				Thereafter: 100,
			}
		}
	}

	return zap.Config{
		Level:            level,
		Development:      development,
		Sampling:         sampling,
		Encoding:         "console",
		EncoderConfig:    NewProductionConsoleEncoderConfig(suppressTimestamps),
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}, nil
}

// NewProductionConsoleEncoderConfig returns an opinionated EncoderConfig for
// production console environments.
func NewProductionConsoleEncoderConfig(suppressTimestamps bool) zapcore.EncoderConfig {
	var (
		timeKey    string
		encodeTime zapcore.TimeEncoder
	)

	if !suppressTimestamps {
		timeKey = "T"
		encodeTime = zapcore.ISO8601TimeEncoder
	}

	return zapcore.EncoderConfig{
		TimeKey:          timeKey,
		LevelKey:         "L",
		NameKey:          "N",
		CallerKey:        "C",
		FunctionKey:      zapcore.OmitKey,
		MessageKey:       "M",
		StacktraceKey:    "S",
		LineEnding:       zapcore.DefaultLineEnding,
		EncodeLevel:      zapcore.CapitalLevelEncoder,
		EncodeTime:       encodeTime,
		EncodeDuration:   zapcore.StringDurationEncoder,
		EncodeCaller:     zapcore.ShortCallerEncoder,
		ConsoleSeparator: " ",
	}
}

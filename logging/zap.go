package logging

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NewProductionConsoleConfig is a reasonable production logging configuration.
// Logging is enabled at InfoLevel and above.
//
// It uses a console encoder, writes to standard error, and enables sampling.
// Stacktraces are automatically included on logs of ErrorLevel and above.
func NewProductionConsoleConfig(suppressTimestamps bool) zap.Config {
	return zap.Config{
		Level:       zap.NewAtomicLevelAt(zap.InfoLevel),
		Development: false,
		Sampling: &zap.SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		},
		Encoding:         "console",
		EncoderConfig:    NewProductionConsoleEncoderConfig(suppressTimestamps),
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}
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
		EncodeLevel:      zapcore.CapitalColorLevelEncoder,
		EncodeTime:       encodeTime,
		EncodeDuration:   zapcore.StringDurationEncoder,
		EncodeCaller:     zapcore.ShortCallerEncoder,
		ConsoleSeparator: " ",
	}
}

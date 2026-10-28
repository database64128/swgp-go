// Package tslogtest provides utilities for using [tslog] in tests.
package tslogtest

import (
	"log/slog"
	"testing"

	"github.com/database64128/swgp-go/tslog"
)

// NewLogger returns a logger that logs at debug level to the test output.
func NewLogger(t testing.TB) *tslog.Logger {
	t.Helper()
	logCfg := tslog.Config{
		Level: slog.LevelDebug,
	}
	logger, err := logCfg.NewLogger(t.Output())
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	return logger
}

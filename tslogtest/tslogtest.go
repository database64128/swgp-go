// Package tslogtest provides utilities for using [tslog] in tests.
package tslogtest

import "github.com/database64128/swgp-go/tslog"

// Config is [tslog.Config] for use in tests.
type Config tslog.Config

// NewTestLogger creates a new [*Logger] for use in tests.
func (c Config) NewTestLogger(t testingLogger) *tslog.Logger {
	return tslog.Config(c).NewLogger(newTestingWriter(t))
}

type testingLogger interface {
	Logf(format string, args ...any)
}

type testingWriter struct {
	t testingLogger
}

func newTestingWriter(t testingLogger) testingWriter {
	return testingWriter{t}
}

func (w testingWriter) Write(p []byte) (n int, err error) {
	w.t.Logf("%s", p)
	return len(p), nil
}

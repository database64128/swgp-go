//go:build linux

package main

import (
	"github.com/database64128/swgp-go/service"
	"go.uber.org/zap"
)

func initHook(config service.Config, logger *zap.Logger) {
	// NOOP
}

func cleanerHook(config service.Config, logger *zap.Logger) {
	// NOOP
}

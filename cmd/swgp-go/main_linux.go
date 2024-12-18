//go:build linux

package main

import (
	"github.com/database64128/swgp-go/service"
	"github.com/database64128/swgp-go/tslog"
)

func initHook(config service.Config, logger *tslog.Logger) {
	// NOOP
}

func cleanerHook() {
	// NOOP
}

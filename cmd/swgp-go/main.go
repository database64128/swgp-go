package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/database64128/swgp-go"
	"github.com/database64128/swgp-go/jsoncfg"
	"github.com/database64128/swgp-go/service"
	"github.com/database64128/swgp-go/tslog"
)

var (
	version    bool
	fmtConf    bool
	testConf   bool
	logNoColor bool
	logNoTime  bool
	logFormat  tslog.Format
	logLevel   slog.Level
	confPath   string
)

func init() {
	flag.BoolVar(&version, "version", false, "Print version and exit")
	flag.BoolVar(&fmtConf, "fmtConf", false, "Format the configuration file")
	flag.BoolVar(&testConf, "testConf", false, "Test the configuration file and exit")
	flag.BoolVar(&logNoColor, "logNoColor", false, "Disable colors in log output")
	flag.BoolVar(&logNoTime, "logNoTime", false, "Disable timestamps in log output")
	flag.TextVar(&logFormat, "logFormat", tslog.FormatDefault, "Log format, one of: default, slog-text, slog-json, tint-text")
	flag.TextVar(&logLevel, "logLevel", slog.LevelInfo, "Log level, one of: DEBUG, INFO, WARN, ERROR")
	flag.StringVar(&confPath, "confPath", "config.json", "Path to the configuration file")
}

func main() {
	flag.Parse()

	if version {
		os.Stdout.WriteString("swgp-go\t" + swgp.Version + "\n")
		if info, ok := debug.ReadBuildInfo(); ok {
			os.Stdout.WriteString(info.String())
		}
		return
	}

	logCfg := tslog.Config{
		Level:   logLevel,
		NoColor: logNoColor,
		NoTime:  logNoTime,
		Format:  logFormat,
	}
	logger, err := logCfg.NewLogger(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create logger: %v\n", err)
		os.Exit(1)
	}
	logger.Info("swgp-go", slog.String("version", swgp.Version))

	var sc service.Config
	if err := jsoncfg.Load(confPath, &sc); err != nil {
		logger.Error("Failed to load config",
			slog.String("path", confPath),
			tslog.Err(err),
		)
		os.Exit(1)
	}

	if fmtConf {
		if err := jsoncfg.Save(confPath, &sc); err != nil {
			logger.Error("Failed to save config",
				slog.String("path", confPath),
				tslog.Err(err),
			)
			os.Exit(1)
		}
		logger.Info("Formatted configuration file", slog.String("path", confPath))
	}

	m, err := sc.Manager(logger)
	if err != nil {
		logger.Error("Failed to create service manager", tslog.Err(err))
		os.Exit(1)
	}

	if testConf {
		logger.Info("Configuration file is valid")
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	_ = context.AfterFunc(ctx, func() {
		stop()
	})

	if err = m.Run(ctx); err != nil {
		os.Exit(1)
	}
}

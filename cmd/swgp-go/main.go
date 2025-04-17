package main

import (
	"context"
	"flag"
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
	logKVPairs bool
	logJSON    bool
	logLevel   slog.Level
	confPath   string
)

func init() {
	flag.BoolVar(&version, "version", false, "Print version and exit")
	flag.BoolVar(&fmtConf, "fmtConf", false, "Format the configuration file")
	flag.BoolVar(&testConf, "testConf", false, "Test the configuration file and exit")
	flag.BoolVar(&logNoColor, "logNoColor", false, "Disable colors in log output")
	flag.BoolVar(&logNoTime, "logNoTime", false, "Disable timestamps in log output")
	flag.BoolVar(&logKVPairs, "logKVPairs", false, "Use key=value pairs in log output")
	flag.BoolVar(&logJSON, "logJSON", false, "Use JSON in log output")
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
		Level:          logLevel,
		NoColor:        logNoColor,
		NoTime:         logNoTime,
		UseTextHandler: logKVPairs,
		UseJSONHandler: logJSON,
	}
	logger := logCfg.NewLogger(os.Stderr)
	logger.Info("swgp-go", slog.String("version", swgp.Version))

	var sc service.Config
	if err := jsoncfg.Open(confPath, &sc); err != nil {
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

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		logger.Info("Received exit signal", slog.Any("signal", sig))
		signal.Stop(sigCh)
		cancel()
	}()

	if err = m.Run(ctx); err != nil {
		os.Exit(1)
	}
}

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/database64128/swgp-go/jsonhelper"
	"github.com/database64128/swgp-go/logging"
	"github.com/database64128/swgp-go/service"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	testConf bool
	confPath string
	zapConf  string
	logLevel zapcore.Level
)

func init() {
	flag.BoolVar(&testConf, "testConf", false, "Test the configuration file without starting the services")
	flag.StringVar(&confPath, "confPath", "", "Path to JSON configuration file")
	flag.StringVar(&zapConf, "zapConf", "", "Preset name or path to JSON configuration file for building the zap logger.\nAvailable presets: console (default), systemd, production, development")
	flag.TextVar(&logLevel, "logLevel", zapcore.InvalidLevel, "Override the logger configuration's log level.\nAvailable levels: debug, info, warn, error, dpanic, panic, fatal")
}

func main() {
	flag.Parse()

	if confPath == "" {
		fmt.Println("Missing -confPath <path>.")
		flag.Usage()
		os.Exit(1)
	}

	var (
		zc zap.Config
		sc service.Config
	)

	switch zapConf {
	case "console", "":
		zc = logging.NewProductionConsoleConfig(false)
	case "systemd":
		zc = logging.NewProductionConsoleConfig(true)
	case "production":
		zc = zap.NewProductionConfig()
	case "development":
		zc = zap.NewDevelopmentConfig()
	default:
		if err := jsonhelper.LoadAndDecodeDisallowUnknownFields(zapConf, &zc); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if logLevel != zapcore.InvalidLevel {
		zc.Level.SetLevel(logLevel)
	}

	logger, err := zc.Build()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer logger.Sync()

	if err = jsonhelper.LoadAndDecodeDisallowUnknownFields(confPath, &sc); err != nil {
		logger.Fatal("Failed to load config",
			zap.String("confPath", confPath),
			zap.Error(err),
		)
	}

	m, err := sc.Manager(logger)
	if err != nil {
		logger.Fatal("Failed to create service manager",
			zap.String("confPath", confPath),
			zap.Error(err),
		)
	}

	if testConf {
		logger.Info("Config test OK", zap.String("confPath", confPath))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		logger.Info("Received exit signal", zap.Stringer("signal", sig))
		cancel()
	}()

	if err = m.Start(ctx); err != nil {
		logger.Fatal("Failed to start services",
			zap.String("confPath", confPath),
			zap.Error(err),
		)
	}

	<-ctx.Done()
	m.Stop()
}

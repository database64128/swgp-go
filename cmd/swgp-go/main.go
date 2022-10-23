package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/database64128/swgp-go/logging"
	"github.com/database64128/swgp-go/service"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	confPath = flag.String("confPath", "", "Path to JSON configuration file")
	zapConf  = flag.String("zapConf", "", "Preset name or path to JSON configuration file for building the zap logger.\nAvailable presets: console (default), systemd, production, development")
	logLevel = flag.String("logLevel", "", "Override the logger configuration's log level.\nAvailable levels: debug, info, warn, error, dpanic, panic, fatal")
)

func main() {
	flag.Parse()

	if *confPath == "" {
		fmt.Println("Missing -confPath <path>.")
		flag.Usage()
		os.Exit(1)
	}

	var (
		zc zap.Config
		sc service.Config
	)

	switch *zapConf {
	case "console", "":
		zc = logging.NewProductionConsoleConfig(false)
	case "systemd":
		zc = logging.NewProductionConsoleConfig(true)
	case "production":
		zc = zap.NewProductionConfig()
	case "development":
		zc = zap.NewDevelopmentConfig()
	default:
		f, err := os.Open(*zapConf)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		d := json.NewDecoder(f)
		d.DisallowUnknownFields()
		err = d.Decode(&zc)
		f.Close()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if *logLevel != "" {
		l, err := zapcore.ParseLevel(*logLevel)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		zc.Level.SetLevel(l)
	}

	logger, err := zc.Build()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer logger.Sync()

	f, err := os.Open(*confPath)
	if err != nil {
		logger.Fatal("Failed to open config file",
			zap.Stringp("confPath", confPath),
			zap.Error(err),
		)
	}

	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	err = d.Decode(&sc)
	f.Close()
	if err != nil {
		logger.Fatal("Failed to decode config",
			zap.Stringp("confPath", confPath),
			zap.Error(err),
		)
	}

	m, err := sc.Manager(logger)
	if err != nil {
		logger.Fatal("Failed to create service manager",
			zap.Stringp("confPath", confPath),
			zap.Error(err),
		)
	}

	if err = m.Start(); err != nil {
		logger.Fatal("Failed to start services",
			zap.Stringp("confPath", confPath),
			zap.Error(err),
		)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	logger.Info("Received signal, stopping...", zap.Stringer("signal", sig))

	m.Stop()
}

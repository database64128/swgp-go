package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/database64128/swgp-go/logging"
	"github.com/database64128/swgp-go/service"
	"go.uber.org/zap"
)

var (
	confPath           = flag.String("confPath", "", "Path to JSON configuration file")
	suppressTimestamps = flag.Bool("suppressTimestamps", false, "Omit timestamps in logs")
	logLevel           = flag.String("logLevel", "info", "Set custom log level. Available levels: debug, info, warn, error, dpanic, panic, fatal")
)

func main() {
	flag.Parse()

	if *confPath == "" {
		fmt.Println("Missing -confPath <path>.")
		flag.Usage()
		return
	}

	if *suppressTimestamps {
		log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	}

	logger, err := logging.NewProductionConsole(*suppressTimestamps, *logLevel)
	if err != nil {
		log.Fatal(err)
	}
	defer logger.Sync()

	cj, err := os.ReadFile(*confPath)
	if err != nil {
		logger.Fatal("Failed to load config",
			zap.Stringp("confPath", confPath),
			zap.Error(err),
		)
	}

	var sc service.ServiceConfig
	err = json.Unmarshal(cj, &sc)
	if err != nil {
		logger.Fatal("Failed to unmarshal config",
			zap.Stringp("confPath", confPath),
			zap.Error(err),
		)
	}

	err = sc.Start(logger)
	if err != nil {
		logger.Fatal("Failed to start configured services",
			zap.Stringp("confPath", confPath),
			zap.Error(err),
		)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	logger.Info("Received signal, stopping...", zap.Stringer("signal", sig))

	sc.Stop()
}

//go:build darwin

package main

import (
	"errors"
	"github.com/database64128/swgp-go/service"
	"go.uber.org/zap"
	"golang.org/x/net/route"
	"net"
	"os/exec"
	"syscall"
	"time"
)

func discoverGateway() (ip net.IP, err error) {
	rib, err := route.FetchRIB(syscall.AF_INET, syscall.NET_RT_DUMP, 0)
	if err != nil {
		return nil, err
	}

	msgs, err := route.ParseRIB(syscall.NET_RT_DUMP, rib)
	if err != nil {
		return nil, err
	}

	for _, m := range msgs {
		switch m := m.(type) {
		case *route.RouteMessage:
			var ip net.IP
			switch sa := m.Addrs[syscall.RTAX_GATEWAY].(type) {
			case *route.Inet4Addr:
				ip = net.IPv4(sa.IP[0], sa.IP[1], sa.IP[2], sa.IP[3])
				return ip, nil
			case *route.Inet6Addr:
				ip = make(net.IP, net.IPv6len)
				copy(ip, sa.IP[:])
				return ip, nil
			}
		}
	}
	return nil, errors.New("no ip found")
}

func executeCommands(logger *zap.Logger, commands []string) error {
	for _, cmdStr := range commands {
		cmd := exec.Command("bash", "-c", cmdStr)
		// Run the command and capture its output.
		output, err := cmd.CombinedOutput()
		if err != nil {
			return err
		}
		logger.Info("Command executed", zap.String("output", string(output)))
	}
	return nil
}

func addGatewayRoute(cfg *service.Config, logger *zap.Logger, gatewayIp net.IP, err error) {
	for _, client := range cfg.Clients {
		commands := []string{
			"sudo route delete " + client.ProxyEndpointAddress.IP().String(),
			"sudo route add " + client.ProxyEndpointAddress.IP().String() + "/32 " + gatewayIp.String(),
		}
		err = executeCommands(logger, commands)
		if err != nil {
			logger.Error("Failed to recreate route:", zap.Error(err))
		}
	}
}

func deleteGatewayRoute(cfg *service.Config, logger *zap.Logger) {
	for _, client := range cfg.Clients {
		err := executeCommands(logger, []string{"sudo route delete " + client.ProxyEndpointAddress.IP().String()})
		if err != nil {
			logger.Error("Failed to delete route:", zap.Error(err))
		}
	}
}

var macGateway = gatewayMonitor{}

type gatewayMonitor struct {
	ip        net.IP
	logger    *zap.Logger
	cfg       *service.Config
	cancelled chan struct{}
}

func (g *gatewayMonitor) watch() {
	for {
		select {
		case <-g.cancelled:
			return
		default:
			ip, err := discoverGateway()
			if err != nil {
				g.logger.Error("Failed to get Gateway address:", zap.Error(err))
			}
			if !g.ip.Equal(ip) {
				g.logger.Info("Gateway address changed, reconfiguring routes")
				deleteGatewayRoute(g.cfg, g.logger)
				addGatewayRoute(g.cfg, g.logger, ip, err)

				// update ip
				g.ip = ip
			}
			// sleep for 10 seconds
			time.Sleep(10 * time.Second)

			// show current gateway route
			g.logger.Info("Current gateway route:" + ip.String())
		}
	}
}

// add route
func initHook(cfg *service.Config, logger *zap.Logger) {
	gatewayIp, err := discoverGateway()
	if err != nil {
		logger.Fatal("Failed to get Gateway address:", zap.Error(err))
	}
	addGatewayRoute(cfg, logger, gatewayIp, err)
	macGateway.ip = gatewayIp
	macGateway.logger = logger
	macGateway.cfg = cfg
	macGateway.cancelled = make(chan struct{})
	go macGateway.watch()
}

func cleanupHook(cfg *service.Config, logger *zap.Logger) {
	deleteGatewayRoute(cfg, logger)

	// cancel gateway monitor
	close(macGateway.cancelled)
}

//go:build darwin

package main

import (
	"errors"
	"fmt"
	"github.com/database64128/swgp-go/service"
	"go.uber.org/zap"
	"golang.org/x/net/route"
	"net"
	"os/exec"
	"syscall"
	"time"
)

func discoverGateway() (net.IP, error) {
	rib, err := route.FetchRIB(syscall.AF_INET, syscall.NET_RT_DUMP, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch RIB: %v", err)
	}

	msgs, err := route.ParseRIB(syscall.NET_RT_DUMP, rib)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RIB: %v", err)
	}

	var ips []net.IP

	for _, m := range msgs {
		if rm, ok := m.(*route.RouteMessage); ok {
			if rm.Flags&syscall.RTF_GATEWAY != 0 && rm.Flags&syscall.RTF_UP != 0 {
				addr := rm.Addrs[syscall.RTAX_GATEWAY]
				switch sa := addr.(type) {
				case *route.Inet4Addr:
					ips = append(ips, net.IPv4(sa.IP[0], sa.IP[1], sa.IP[2], sa.IP[3]))
				case *route.Inet6Addr:
					ip := make(net.IP, net.IPv6len)
					copy(ip, sa.IP[:])
					ips = append(ips, ip)
				}
			}
		}
	}
	if len(ips) > 0 {
		return ips[0], nil
	}
	return nil, errors.New("no default gateway found")
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

func addGatewayRoute(cfg *service.Config, logger *zap.Logger, gatewayIP net.IP) error {
	logger.Info("Current gateway route:" + gatewayIP.String())
	for _, client := range cfg.Clients {
		var commands []string
		if gatewayIP.To4() != nil {
			// IPv4 gateway
			commands = []string{
				"sudo route -n delete -net " + client.ProxyEndpointAddress.IP().String(),
				"sudo route -n add -net " + client.ProxyEndpointAddress.IP().String() + "/32 -gateway " + gatewayIP.String(),
			}
		} else {
			// IPv6 gateway
			commands = []string{
				"sudo route -n delete -inet6 -net " + client.ProxyEndpointAddress.IP().String(),
				"sudo route -n add -inet6 -net " + client.ProxyEndpointAddress.IP().String() + "/128 -gateway " + gatewayIP.String(),
			}
		}
		err := executeCommands(logger, commands)
		if err != nil {
			return fmt.Errorf("failed to recreate route for client %s: %v", client.ProxyEndpointAddress.IP().String(), err)
		}
	}
	return nil
}

func deleteGatewayRoute(cfg *service.Config, logger *zap.Logger) {
	for _, client := range cfg.Clients {
		err := executeCommands(logger, []string{"sudo route -n delete -net " + client.ProxyEndpointAddress.IP().String()})
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
				err = addGatewayRoute(g.cfg, g.logger, ip)
				if err != nil {
					g.logger.Error("Failed to reconfigure routes:", zap.Error(err))
				}

				// update ip
				g.ip = ip
			}

			// sleep for 10 seconds
			time.Sleep(10 * time.Second)
		}
	}
}

// add route
func initHook(cfg *service.Config, logger *zap.Logger) {
	gatewayIp, err := discoverGateway()
	if err != nil {
		logger.Fatal("Failed to get Gateway address:", zap.Error(err))
	}
	err = addGatewayRoute(cfg, logger, gatewayIp)
	if err != nil {
		logger.Fatal("Falied to add gateway route:", zap.Error(err))
	}
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

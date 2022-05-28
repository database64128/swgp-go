// Package service consists of encapsulations that utilize packet handlers
// to provide swgp service over a connection or other abstractions.
package service

import (
	"errors"
	"fmt"
	"time"

	"github.com/database64128/swgp-go/packet"
	"go.uber.org/zap"
)

// sendChannelCapacity defines client and server NAT entry's send channel capacity.
const sendChannelCapacity = 1024

// We use WireGuard's RejectAfterTime as NAT timeout.
const RejectAfterTime = 180 * time.Second

// Used to calculate max packet size from MTU.
const (
	IPv4HeaderLength            = 20
	IPv6HeaderLength            = 40
	UDPHeaderLength             = 8
	WireGuardDataPacketOverhead = 32

	// WireGuard pads data packets so the length is always a multiple of 16.
	WireGuardDataPacketLengthMask = 0xFFF0
)

var ErrMTUTooSmall = errors.New("MTU must be at least 1280")

// Service is implemented by encapsulations that utilize packet handlers
// to provide swgp service over a connection or other abstractions.
type Service interface {
	// String returns the service's name.
	// This method may be called on a nil pointer.
	String() string

	// Start starts the service.
	Start() error

	// Stop stops the service.
	Stop() error
}

// ServiceConfig stores configurations for a typical swgp service.
// It may be marshaled as or unmarshaled from JSON.
// Call the Start method to start all configured services.
// Call the Stop method to properly close all running services.
type ServiceConfig struct {
	Interfaces []ServerConfig `json:"interfaces"`
	Peers      []ClientConfig `json:"peers"`
	services   []Service
	logger     *zap.Logger
}

// Start starts all configured server (interface) and client (peer) services.
func (sc *ServiceConfig) Start(logger *zap.Logger) error {
	sc.logger = logger
	serverCount := len(sc.Interfaces)
	clientCount := len(sc.Peers)
	serviceCount := serverCount + clientCount
	if serviceCount == 0 {
		return errors.New("no services to start")
	}

	sc.services = make([]Service, serviceCount)

	for i := range sc.Interfaces {
		s := NewServerService(sc.Interfaces[i], logger)
		sc.services[i] = s

		err := s.Start()
		if err != nil {
			return fmt.Errorf("failed to start %s: %w", s.String(), err)
		}
	}

	for i := range sc.Peers {
		c := NewClientService(sc.Peers[i], logger)
		sc.services[serverCount+i] = c

		err := c.Start()
		if err != nil {
			return fmt.Errorf("failed to start %s: %w", c.String(), err)
		}
	}

	return nil
}

// Stop stops all running services.
func (sc *ServiceConfig) Stop() {
	for _, s := range sc.services {
		err := s.Stop()
		if err != nil {
			sc.logger.Warn("An error occurred while stopping service",
				zap.Stringer("service", s),
				zap.NamedError("stopError", err),
			)
		}
		sc.logger.Info("Stopped service", zap.Stringer("service", s))
	}
}

func getPacketHandlerForProxyMode(proxyMode string, proxyPSK []byte) (handler packet.Handler, err error) {
	switch proxyMode {
	case "zero-overhead":
		handler, err = packet.NewZeroOverheadHandler(proxyPSK)
	case "paranoid":
		handler, err = packet.NewParanoidHandler(proxyPSK)
	default:
		err = fmt.Errorf("unknown proxy mode: %s", proxyMode)
	}
	return
}

// queuedPacket is the structure used by send channels to queue packets for sending.
type queuedPacket struct {
	bufp   *[]byte
	start  int
	length int
}

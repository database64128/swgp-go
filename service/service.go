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

const (
	// minimumMTU is the minimum allowed MTU.
	minimumMTU = 1280

	// sendChannelCapacity defines client and server NAT entry's send channel capacity.
	sendChannelCapacity = 1024
)

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

// Config stores configurations for a typical swgp service.
// It may be marshaled as or unmarshaled from JSON.
type Config struct {
	Interfaces []ServerConfig `json:"interfaces"`
	Peers      []ClientConfig `json:"peers"`
}

// Manager initializes the service manager.
func (sc *Config) Manager(logger *zap.Logger) (*Manager, error) {
	serverCount := len(sc.Interfaces)
	clientCount := len(sc.Peers)
	serviceCount := serverCount + clientCount
	if serviceCount == 0 {
		return nil, errors.New("no services to start")
	}

	services := make([]Service, serviceCount)

	for i := range sc.Interfaces {
		s, err := NewServerService(sc.Interfaces[i], logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create server service %s: %w", sc.Interfaces[i].Name, err)
		}
		services[i] = s
	}

	for i := range sc.Peers {
		c, err := NewClientService(sc.Peers[i], logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create client service %s: %w", sc.Peers[i].Name, err)
		}
		services[serverCount+i] = c
	}

	return &Manager{services, logger}, nil
}

// Manager manages the services.
type Manager struct {
	services []Service
	logger   *zap.Logger
}

// Start starts all configured server (interface) and client (peer) services.
func (m *Manager) Start() error {
	for _, s := range m.services {
		if err := s.Start(); err != nil {
			return fmt.Errorf("failed to start %s: %w", s.String(), err)
		}
	}
	return nil
}

// Stop stops all running services.
func (m *Manager) Stop() {
	for _, s := range m.services {
		if err := s.Stop(); err != nil {
			m.logger.Warn("Failed to stop service",
				zap.Stringer("service", s),
				zap.Error(err),
			)
		}
		m.logger.Info("Stopped service", zap.Stringer("service", s))
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

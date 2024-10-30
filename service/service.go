// Package service consists of encapsulations that utilize packet handlers
// to provide swgp service over a connection or other abstractions.
package service

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/database64128/swgp-go/conn"
	"github.com/database64128/swgp-go/packet"
	"github.com/database64128/swgp-go/pprof"
	"go.uber.org/zap"
)

const (
	// minimumMTU is the minimum allowed MTU.
	minimumMTU = 1280

	// defaultRelayBatchSize is the default batch size of recvmmsg(2) and sendmmsg(2) calls in relay sessions.
	//
	// On an i9-13900K, the average number of messages received in a single recvmmsg(2) call is
	// around 100 in iperf3 tests. Bumping the msgvec size to greater than 256 does not seem to
	// yield any performance improvement.
	//
	// Note that the mainline iperf3 does not use sendmmsg(2) or io_uring for batch sending at the
	// time of writing. So this value is still subject to change in the future.
	defaultRelayBatchSize = 256

	// defaultMainRecvBatchSize is the default batch size of a relay service's main receive routine.
	defaultMainRecvBatchSize = 64

	// defaultSendChannelCapacity is the default capacity of a relay session's uplink send channel.
	defaultSendChannelCapacity = 1024
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
	String() string

	// Start starts the service.
	Start(ctx context.Context) error

	// Stop stops the service.
	Stop() error
}

// PerfConfig exposes performance tuning knobs.
type PerfConfig struct {
	// BatchMode controls the mode of batch receiving and sending.
	//
	// Available values:
	// - "": Platform default.
	// - "no": Do not receive or send packets in batches.
	// - "sendmmsg": Use recvmmsg(2) and sendmmsg(2) calls. This is the default on Linux and NetBSD.
	BatchMode string `json:"batchMode"`

	// RelayBatchSize is the batch size of recvmmsg(2) and sendmmsg(2) calls in relay sessions.
	RelayBatchSize int `json:"relayBatchSize"`

	// MainRecvBatchSize is the batch size of a relay service's main receive routine.
	MainRecvBatchSize int `json:"mainRecvBatchSize"`

	// SendChannelCapacity is the capacity of a relay session's uplink send channel.
	SendChannelCapacity int `json:"sendChannelCapacity"`

	// DisableUDPGSO disables UDP Generic Segmentation Offload (GSO) on the listener.
	//
	// UDP GSO is enabled by default when available.
	DisableUDPGSO bool `json:"disableUDPGSO"`

	// DisableUDPGRO disables UDP Generic Receive Offload (GRO) on the listener.
	//
	// UDP GRO is enabled by default when available.
	DisableUDPGRO bool `json:"disableUDPGRO"`
}

// CheckAndApplyDefaults checks and applies default values to the configuration.
func (pc *PerfConfig) CheckAndApplyDefaults() error {
	switch pc.BatchMode {
	case "", "no", "sendmmsg":
	default:
		return fmt.Errorf("unknown batch mode: %s", pc.BatchMode)
	}

	// About the batch sizes:
	//
	// On Linux, the sendmmsg(2) syscall can process up to UIO_MAXIOV (1024) messages at once.
	// Passing a vlen value greater than UIO_MAXIOV is allowed, but the kernel will silently truncate it.
	// The recvmmsg(2) syscall does not have a defined limit on vlen, but it does not make much sense to
	// do more than that.

	switch {
	case pc.RelayBatchSize > 0 && pc.RelayBatchSize <= 1024:
	case pc.RelayBatchSize == 0:
		pc.RelayBatchSize = defaultRelayBatchSize
	default:
		return fmt.Errorf("relay batch size out of range [0, 1024]: %d", pc.RelayBatchSize)
	}

	switch {
	case pc.MainRecvBatchSize > 0 && pc.MainRecvBatchSize <= 1024:
	case pc.MainRecvBatchSize == 0:
		pc.MainRecvBatchSize = defaultMainRecvBatchSize
	default:
		return fmt.Errorf("main recv batch size out of range [0, 1024]: %d", pc.MainRecvBatchSize)
	}

	switch {
	case pc.SendChannelCapacity >= 64:
	case pc.SendChannelCapacity == 0:
		pc.SendChannelCapacity = defaultSendChannelCapacity
	default:
		return fmt.Errorf("send channel capacity must be at least 64: %d", pc.SendChannelCapacity)
	}

	return nil
}

// Config stores configurations for a typical swgp service.
// It may be marshaled as or unmarshaled from JSON.
type Config struct {
	Servers []ServerConfig `json:"servers"`
	Clients []ClientConfig `json:"clients"`
	Pprof   pprof.Config   `json:"pprof"`
}

// Manager initializes the service manager.
func (sc *Config) Manager(logger *zap.Logger) (*Manager, error) {
	serviceCount := len(sc.Servers) + len(sc.Clients)
	if sc.Pprof.Enabled {
		serviceCount++
	}
	if serviceCount == 0 {
		return nil, errors.New("no services to start")
	}

	services := make([]Service, 0, serviceCount)
	listenConfigCache := conn.NewListenConfigCache()

	for i := range sc.Servers {
		s, err := sc.Servers[i].Server(logger, listenConfigCache)
		if err != nil {
			return nil, fmt.Errorf("failed to create server service %s: %w", sc.Servers[i].Name, err)
		}
		services = append(services, s)
	}

	for i := range sc.Clients {
		c, err := sc.Clients[i].Client(logger, listenConfigCache)
		if err != nil {
			return nil, fmt.Errorf("failed to create client service %s: %w", sc.Clients[i].Name, err)
		}
		services = append(services, c)
	}

	if sc.Pprof.Enabled {
		services = append(services, sc.Pprof.NewService(logger))
	}

	return &Manager{services, logger}, nil
}

// Manager manages the services.
type Manager struct {
	services []Service
	logger   *zap.Logger
}

// Start starts all configured server (interface) and client (peer) services.
func (m *Manager) Start(ctx context.Context) error {
	for _, s := range m.services {
		if err := s.Start(ctx); err != nil {
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

func newPacketHandler(proxyMode string, proxyPSK []byte, maxPacketSize int) (packet.Handler, error) {
	switch proxyMode {
	case "zero-overhead":
		return packet.NewZeroOverheadHandler(proxyPSK, maxPacketSize)
	case "paranoid":
		return packet.NewParanoidHandler(proxyPSK, maxPacketSize)
	default:
		return nil, fmt.Errorf("unknown proxy mode: %s", proxyMode)
	}
}

func wgTunnelMTUFromMaxPacketSize(maxPacketSize int) int {
	return (maxPacketSize - WireGuardDataPacketOverhead) & WireGuardDataPacketLengthMask
}

func listenUDPNetworkForRemoteAddr(remoteAddr netip.Addr) string {
	if remoteAddr.Is4() || remoteAddr.Is4In6() {
		return "udp4"
	}
	return "udp6"
}

// queuedPacket is the structure used by send channels to queue packets for sending.
type queuedPacket struct {
	// buf is the buffer containing the packet.
	buf []byte

	// segmentSize is the size of each segment in buf.
	// The last segment may be smaller than segmentSize.
	// If buf is not segmented, segmentSize is len(buf).
	segmentSize uint32

	// segmentCount is the number of segments in buf.
	// If buf is not segmented, segmentCount is 1.
	segmentCount uint32
}

// isWireGuardHandshakeInitiationMessage walks all segments and returns true if any segment is a WireGuard handshake initiation message.
func (qp *queuedPacket) isWireGuardHandshakeInitiationMessage() bool {
	if qp.segmentSize == 0 {
		return false
	}
	for i := 0; i < len(qp.buf); i += int(qp.segmentSize) {
		if qp.buf[i] == packet.WireGuardMessageTypeHandshakeInitiation {
			return true
		}
	}
	return false
}

// pktinfo stores packet information for sending from the correct interface and IP.
type pktinfo struct {
	addr    netip.Addr
	ifindex uint32
}

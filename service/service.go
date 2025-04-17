// Package service consists of encapsulations that utilize packet handlers
// to provide swgp service over a connection or other abstractions.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/database64128/swgp-go/conn"
	"github.com/database64128/swgp-go/packet"
	"github.com/database64128/swgp-go/pprof"
	"github.com/database64128/swgp-go/tslog"
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
	// SlogAttr returns a [slog.Attr] that identifies the service.
	SlogAttr() slog.Attr

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
	BatchMode string `json:"batchMode,omitzero"`

	// RelayBatchSize is the batch size of recvmmsg(2) and sendmmsg(2) calls in relay sessions.
	RelayBatchSize int `json:"relayBatchSize,omitzero"`

	// MainRecvBatchSize is the batch size of a relay service's main receive routine.
	MainRecvBatchSize int `json:"mainRecvBatchSize,omitzero"`

	// SendChannelCapacity is the capacity of a relay session's uplink send channel.
	SendChannelCapacity int `json:"sendChannelCapacity,omitzero"`

	// DisableUDPGSO disables UDP Generic Segmentation Offload (GSO) on the listener.
	//
	// UDP GSO is enabled by default when available.
	DisableUDPGSO bool `json:"disableUDPGSO,omitzero"`

	// DisableUDPGRO disables UDP Generic Receive Offload (GRO) on the listener.
	//
	// UDP GRO is enabled by default when available.
	DisableUDPGRO bool `json:"disableUDPGRO,omitzero"`
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
	Servers []ServerConfig `json:"servers,omitzero"`
	Clients []ClientConfig `json:"clients,omitzero"`
	Pprof   pprof.Config   `json:"pprof,omitzero"`
}

// Manager initializes the service manager.
func (sc *Config) Manager(logger *tslog.Logger) (*Manager, error) {
	serviceCount := len(sc.Servers) + len(sc.Clients)
	if sc.Pprof.Enabled {
		serviceCount++
	}
	if serviceCount == 0 {
		return nil, errors.New("no services to start")
	}

	services := make([]Service, 0, serviceCount)
	serverIndexByName := make(map[string]int, len(sc.Servers))
	clientIndexByName := make(map[string]int, len(sc.Clients))
	listenConfigCache := conn.NewListenConfigCache()

	for i := range sc.Servers {
		serverConfig := &sc.Servers[i]

		if dupIndex, ok := serverIndexByName[serverConfig.Name]; ok {
			return nil, fmt.Errorf("duplicate server name %q at index %d and %d", serverConfig.Name, dupIndex, i)
		}
		serverIndexByName[serverConfig.Name] = i

		s, err := serverConfig.Server(logger, listenConfigCache)
		if err != nil {
			return nil, fmt.Errorf("failed to create server service %q: %w", serverConfig.Name, err)
		}
		services = append(services, s)
	}

	for i := range sc.Clients {
		clientConfig := &sc.Clients[i]

		if dupIndex, ok := clientIndexByName[clientConfig.Name]; ok {
			return nil, fmt.Errorf("duplicate client name %q at index %d and %d", clientConfig.Name, dupIndex, i)
		}
		clientIndexByName[clientConfig.Name] = i

		c, err := clientConfig.Client(logger, listenConfigCache)
		if err != nil {
			return nil, fmt.Errorf("failed to create client service %q: %w", clientConfig.Name, err)
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
	logger   *tslog.Logger
}

// Run starts all services. If any service fails to start, it stops all running services and
// returns an error. On success, it blocks until the context is canceled. The returned error
// can be unwrapped to a slice of [*ManagerError].
func (m *Manager) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var errs []error
	runningSvcs := make([]Service, 0, len(m.services))

	for _, s := range m.services {
		if err := s.Start(ctx); err != nil {
			m.logger.Error("Failed to start service", s.SlogAttr(), tslog.Err(err))
			errs = append(errs, newManagerError("start", s, err))
			cancel()
			break
		}
		runningSvcs = append(runningSvcs, s)
	}

	<-ctx.Done()

	for _, s := range runningSvcs {
		if err := s.Stop(); err != nil {
			m.logger.Error("Failed to stop service", s.SlogAttr(), tslog.Err(err))
			errs = append(errs, newManagerError("stop", s, err))
		}
	}

	return errors.Join(errs...)
}

// ManagerError is the error type returned by [Manager].
type ManagerError struct {
	// Action is one of "start" or "stop".
	Action string

	// Svc is the service that failed.
	Svc Service

	// Err is the error returned by starting or stopping the service.
	Err error
}

func newManagerError(action string, svc Service, err error) *ManagerError {
	return &ManagerError{action, svc, err}
}

func (me *ManagerError) Error() string {
	return fmt.Sprintf("failed to %s %s: %v", me.Action, me.Svc.SlogAttr().String(), me.Err)
}

func (me *ManagerError) Unwrap() error {
	return me.Err
}

func newPacketHandler(proxyMode string, proxyPSK []byte, maxPacketSize int) (packet.Handler, error) {
	switch proxyMode {
	case "zero-overhead":
		return packet.NewZeroOverheadHandler(proxyPSK, maxPacketSize)
	case "paranoid":
		return packet.NewParanoidHandler(proxyPSK, maxPacketSize)
	default:
		return nil, fmt.Errorf("unknown proxy mode: %q", proxyMode)
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

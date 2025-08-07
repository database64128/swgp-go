package conn

import (
	"context"
	"net"
	"syscall"
)

// SocketInfo contains information about a socket.
type SocketInfo struct {
	// MaxUDPGSOSegments is the maximum number of UDP GSO segments supported by the socket.
	//
	// If UDP GSO is not enabled on the socket, or the system does not support UDP GSO, the value is 1.
	//
	// The value is 0 if the socket is not a UDP socket.
	MaxUDPGSOSegments uint32

	// UDPGenericReceiveOffload indicates whether UDP GRO is enabled on the socket.
	UDPGenericReceiveOffload bool
}

type setFunc = func(fd int, network string, info *SocketInfo) error

type setFuncSlice []setFunc

func (fns setFuncSlice) controlContextFunc(info *SocketInfo) func(ctx context.Context, network, address string, c syscall.RawConn) error {
	if len(fns) == 0 {
		return nil
	}
	return func(ctx context.Context, network, address string, c syscall.RawConn) (err error) {
		if cerr := c.Control(func(fd uintptr) {
			for _, fn := range fns {
				if err = fn(int(fd), network, info); err != nil {
					return
				}
			}
		}); cerr != nil {
			return cerr
		}
		return
	}
}

func (fns setFuncSlice) controlFunc(info *SocketInfo) func(network, address string, c syscall.RawConn) error {
	if len(fns) == 0 {
		return nil
	}
	return func(network, address string, c syscall.RawConn) (err error) {
		if cerr := c.Control(func(fd uintptr) {
			for _, fn := range fns {
				if err = fn(int(fd), network, info); err != nil {
					return
				}
			}
		}); cerr != nil {
			return cerr
		}
		return
	}
}

// UDPSocketConfig is like [net.ListenConfig] and [net.Dialer] in one with a subjectively nicer API.
type UDPSocketConfig struct {
	fns setFuncSlice
}

// Listen wraps [net.ListenConfig.ListenPacket] and returns a [*net.UDPConn] directly.
func (cfg *UDPSocketConfig) Listen(ctx context.Context, network, address string) (uc *net.UDPConn, info SocketInfo, err error) {
	network, err = udpNetwork(network)
	if err != nil {
		return nil, info, err
	}

	info.MaxUDPGSOSegments = 1

	nlc := net.ListenConfig{
		Control: cfg.fns.controlFunc(&info),
	}

	pc, err := nlc.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, info, err
	}
	return pc.(*net.UDPConn), info, nil
}

// Dial wraps [net.Dialer.DialContext] and returns a [*net.UDPConn] directly.
func (cfg *UDPSocketConfig) Dial(ctx context.Context, localAddr Addr, network, address string) (uc *net.UDPConn, info SocketInfo, err error) {
	nd := net.Dialer{
		ControlContext: cfg.fns.controlContextFunc(&info),
	}

	if localAddr.IsValid() {
		networkIP, err := ipNetwork(network)
		if err != nil {
			return nil, info, err
		}

		localAddrPort, err := localAddr.ResolveIPPort(ctx, networkIP)
		if err != nil {
			return nil, info, err
		}

		nd.LocalAddr = net.UDPAddrFromAddrPort(localAddrPort)
	}

	network, err = udpNetwork(network)
	if err != nil {
		return nil, info, err
	}

	info.MaxUDPGSOSegments = 1

	c, err := nd.DialContext(ctx, network, address)
	if err != nil {
		return nil, info, err
	}
	return c.(*net.UDPConn), info, nil
}

func ipNetwork(network string) (string, error) {
	switch network {
	case "ip", "ip4", "ip6":
		return network, nil
	case "udp":
		return "ip", nil
	case "udp4":
		return "ip4", nil
	case "udp6":
		return "ip6", nil
	default:
		return "", net.UnknownNetworkError(network)
	}
}

func udpNetwork(network string) (string, error) {
	switch network {
	case "udp", "udp4", "udp6":
		return network, nil
	case "ip":
		return "udp", nil
	case "ip4":
		return "udp4", nil
	case "ip6":
		return "udp6", nil
	default:
		return "", net.UnknownNetworkError(network)
	}
}

// UDPSocketOptions contains UDP-specific socket options.
type UDPSocketOptions struct {
	// SendBufferSize sets the send buffer size of the socket.
	//
	// This is best-effort and does not return an error if the operation fails.
	//
	// Available on POSIX systems.
	SendBufferSize int

	// ReceiveBufferSize sets the receive buffer size of the socket.
	//
	// This is best-effort and does not return an error if the operation fails.
	//
	// Available on POSIX systems.
	ReceiveBufferSize int

	// Fwmark sets the socket's fwmark on Linux, or user cookie on FreeBSD.
	//
	// Available on Linux and FreeBSD.
	Fwmark int

	// TrafficClass sets the traffic class of the socket.
	//
	// Available on most platforms except Windows.
	TrafficClass int

	// PathMTUDiscovery enables Path MTU Discovery on the socket.
	//
	// Available on Linux, macOS, FreeBSD, and Windows.
	PathMTUDiscovery bool

	// ProbeUDPGSOSupport enables best-effort probing of
	// UDP Generic Segmentation Offload (GSO) support on the socket.
	//
	// Available on Linux and Windows.
	ProbeUDPGSOSupport bool

	// UDPGenericReceiveOffload enables UDP Generic Receive Offload (GRO) on the socket.
	//
	// Available on Linux and Windows.
	UDPGenericReceiveOffload bool

	// ReceivePacketInfo enables the reception of packet information control messages on the socket.
	//
	// Available on POSIX systems.
	ReceivePacketInfo bool
}

// socketConfig returns a [UDPSocketConfig] that sets the socket options.
func (opts UDPSocketOptions) socketConfig() UDPSocketConfig {
	return UDPSocketConfig{
		fns: opts.buildSetFns(),
	}
}

// DefaultUDPSocketBufferSize is the default send and receive buffer size of UDP sockets.
//
// We use the same value of 7 MiB as wireguard-go:
// https://github.com/WireGuard/wireguard-go/blob/12269c2761734b15625017d8565745096325392f/conn/controlfns.go#L13-L18
//
// Some platforms will silently clamp the value to other maximums, such as Linux clamping to net.core.{r,w}mem_max.
// Other platforms may return an error, which we simply ignore.
const DefaultUDPSocketBufferSize = 7 << 20

var (
	// DefaultUDPServerSocketOptions is the default [UDPSocketOptions] for UDP servers.
	DefaultUDPServerSocketOptions = UDPSocketOptions{
		SendBufferSize:           DefaultUDPSocketBufferSize,
		ReceiveBufferSize:        DefaultUDPSocketBufferSize,
		PathMTUDiscovery:         true,
		ProbeUDPGSOSupport:       true,
		UDPGenericReceiveOffload: true,
		ReceivePacketInfo:        true,
	}

	// DefaultUDPServerSocketConfig is the default [UDPSocketConfig] for UDP servers.
	DefaultUDPServerSocketConfig = DefaultUDPServerSocketOptions.socketConfig()

	// DefaultUDPClientSocketOptions is the default [UDPSocketOptions] for UDP clients.
	DefaultUDPClientSocketOptions = UDPSocketOptions{
		SendBufferSize:           DefaultUDPSocketBufferSize,
		ReceiveBufferSize:        DefaultUDPSocketBufferSize,
		PathMTUDiscovery:         true,
		ProbeUDPGSOSupport:       true,
		UDPGenericReceiveOffload: true,
	}

	// DefaultUDPClientSocketConfig is the default [UDPSocketConfig] for UDP clients.
	DefaultUDPClientSocketConfig = DefaultUDPClientSocketOptions.socketConfig()
)

// UDPSocketConfigCache is a cache for [UDPSocketConfig] instances.
type UDPSocketConfigCache map[UDPSocketOptions]UDPSocketConfig

// NewUDPSocketConfigCache creates a new cache for [UDPSocketConfig] with a few default entries.
func NewUDPSocketConfigCache() UDPSocketConfigCache {
	return UDPSocketConfigCache{
		DefaultUDPServerSocketOptions: DefaultUDPServerSocketConfig,
		DefaultUDPClientSocketOptions: DefaultUDPClientSocketConfig,
	}
}

// Get returns a [UDPSocketConfig] for the given [UDPSocketOptions].
func (cache UDPSocketConfigCache) Get(opts UDPSocketOptions) (cfg UDPSocketConfig) {
	cfg, ok := cache[opts]
	if ok {
		return cfg
	}
	cfg = opts.socketConfig()
	cache[opts] = cfg
	return cfg
}

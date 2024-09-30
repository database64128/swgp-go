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
	MaxUDPGSOSegments int

	// UDPGenericReceiveOffload indicates whether UDP GRO is enabled on the socket.
	UDPGenericReceiveOffload bool
}

type setFunc = func(fd int, network string, info *SocketInfo) error

type setFuncSlice []setFunc

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

// ListenConfig is like [net.ListenConfig] but provides a subjectively nicer API.
type ListenConfig struct {
	fns setFuncSlice
}

// ListenUDP wraps [net.ListenConfig.ListenPacket] and returns a [*net.UDPConn] directly.
func (lc *ListenConfig) ListenUDP(ctx context.Context, network, address string) (uc *net.UDPConn, info SocketInfo, err error) {
	nlc := net.ListenConfig{
		Control: lc.fns.controlFunc(&info),
	}
	pc, err := nlc.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, info, err
	}
	return pc.(*net.UDPConn), info, nil
}

// ListenerSocketOptions contains listener-specific socket options.
type ListenerSocketOptions struct {
	// SendBufferSize sets the send buffer size of the listener.
	//
	// Available on POSIX systems.
	SendBufferSize int

	// ReceiveBufferSize sets the receive buffer size of the listener.
	//
	// Available on POSIX systems.
	ReceiveBufferSize int

	// Fwmark sets the listener's fwmark on Linux, or user cookie on FreeBSD.
	//
	// Available on Linux and FreeBSD.
	Fwmark int

	// TrafficClass sets the traffic class of the listener.
	//
	// Available on most platforms except Windows.
	TrafficClass int

	// PathMTUDiscovery enables Path MTU Discovery on the listener.
	//
	// Available on Linux, macOS, FreeBSD, and Windows.
	PathMTUDiscovery bool

	// ProbeUDPGSOSupport enables best-effort probing of
	// UDP Generic Segmentation Offload (GSO) support on the listener.
	//
	// Available on Linux and Windows.
	ProbeUDPGSOSupport bool

	// UDPGenericReceiveOffload enables UDP Generic Receive Offload (GRO) on the listener.
	//
	// Available on Linux and Windows.
	UDPGenericReceiveOffload bool

	// ReceivePacketInfo enables the reception of packet information control messages on the listener.
	//
	// Available on Linux, macOS, and Windows.
	ReceivePacketInfo bool
}

// ListenConfig returns a [ListenConfig] that sets the socket options.
func (lso ListenerSocketOptions) ListenConfig() ListenConfig {
	return ListenConfig{
		fns: lso.buildSetFns(),
	}
}

// DefaultUDPSocketBufferSize is the default send and receive buffer size of UDP sockets.
//
// We use the same value of 7 MiB as wireguard-go:
// https://github.com/WireGuard/wireguard-go/blob/12269c2761734b15625017d8565745096325392f/conn/controlfns.go#L13-L18
const DefaultUDPSocketBufferSize = 7 << 20

var (
	// DefaultUDPServerSocketOptions is the default [ListenerSocketOptions] for UDP servers.
	DefaultUDPServerSocketOptions = ListenerSocketOptions{
		SendBufferSize:    DefaultUDPSocketBufferSize,
		ReceiveBufferSize: DefaultUDPSocketBufferSize,
		PathMTUDiscovery:  true,
		ReceivePacketInfo: true,
	}

	// DefaultUDPServerListenConfig is the default [ListenConfig] for UDP servers.
	DefaultUDPServerListenConfig = DefaultUDPServerSocketOptions.ListenConfig()

	// DefaultUDPClientSocketOptions is the default [ListenerSocketOptions] for UDP clients.
	DefaultUDPClientSocketOptions = ListenerSocketOptions{
		SendBufferSize:    DefaultUDPSocketBufferSize,
		ReceiveBufferSize: DefaultUDPSocketBufferSize,
		PathMTUDiscovery:  true,
	}

	// DefaultUDPClientListenConfig is the default [ListenConfig] for UDP clients.
	DefaultUDPClientListenConfig = DefaultUDPClientSocketOptions.ListenConfig()
)

// ListenConfigCache is a map of [ListenerSocketOptions] to [ListenConfig].
type ListenConfigCache map[ListenerSocketOptions]ListenConfig

// NewListenConfigCache creates a new cache for [ListenConfig] with a few default entries.
func NewListenConfigCache() ListenConfigCache {
	return ListenConfigCache{
		DefaultUDPServerSocketOptions: DefaultUDPServerListenConfig,
		DefaultUDPClientSocketOptions: DefaultUDPClientListenConfig,
	}
}

// Get returns a [ListenConfig] for the given [ListenerSocketOptions].
func (cache ListenConfigCache) Get(lso ListenerSocketOptions) (lc ListenConfig) {
	lc, ok := cache[lso]
	if ok {
		return
	}
	lc = lso.ListenConfig()
	cache[lso] = lc
	return
}

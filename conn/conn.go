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

// ListenConfig is like [net.ListenConfig] but provides a subjectively nicer API.
type ListenConfig struct {
	fns setFuncSlice
}

// ListenUDP wraps [net.ListenConfig.ListenPacket] and returns a [*net.UDPConn] directly.
func (lc *ListenConfig) ListenUDP(ctx context.Context, network, address string) (uc *net.UDPConn, info SocketInfo, err error) {
	info.MaxUDPGSOSegments = 1
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
	// This is best-effort and does not return an error if the operation fails.
	//
	// Available on POSIX systems.
	SendBufferSize int

	// ReceiveBufferSize sets the receive buffer size of the listener.
	//
	// This is best-effort and does not return an error if the operation fails.
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
	// Available on POSIX systems.
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
//
// Some platforms will silently clamp the value to other maximums, such as Linux clamping to net.core.{r,w}mem_max.
// Other platforms may return an error, which we simply ignore.
const DefaultUDPSocketBufferSize = 7 << 20

var (
	// DefaultUDPServerSocketOptions is the default [ListenerSocketOptions] for UDP servers.
	DefaultUDPServerSocketOptions = ListenerSocketOptions{
		SendBufferSize:           DefaultUDPSocketBufferSize,
		ReceiveBufferSize:        DefaultUDPSocketBufferSize,
		PathMTUDiscovery:         true,
		ProbeUDPGSOSupport:       true,
		UDPGenericReceiveOffload: true,
		ReceivePacketInfo:        true,
	}

	// DefaultUDPServerListenConfig is the default [ListenConfig] for UDP servers.
	DefaultUDPServerListenConfig = DefaultUDPServerSocketOptions.ListenConfig()

	// DefaultUDPClientSocketOptions is the default [ListenerSocketOptions] for UDP clients.
	DefaultUDPClientSocketOptions = ListenerSocketOptions{
		SendBufferSize:           DefaultUDPSocketBufferSize,
		ReceiveBufferSize:        DefaultUDPSocketBufferSize,
		PathMTUDiscovery:         true,
		ProbeUDPGSOSupport:       true,
		UDPGenericReceiveOffload: true,
	}

	// DefaultUDPClientListenConfig is the default [ListenConfig] for UDP clients.
	DefaultUDPClientListenConfig = DefaultUDPClientSocketOptions.ListenConfig()
)

// Dialer is like [net.Dialer] but provides a subjectively nicer API.
type Dialer struct {
	fns setFuncSlice
}

// DialUDP wraps [net.Dialer.DialContext] and returns a [*net.UDPConn] directly.
func (d *Dialer) DialUDP(ctx context.Context, network, address string) (uc *net.UDPConn, info SocketInfo, err error) {
	info.MaxUDPGSOSegments = 1
	nd := net.Dialer{
		ControlContext: d.fns.controlContextFunc(&info),
	}
	c, err := nd.DialContext(ctx, network, address)
	if err != nil {
		return nil, info, err
	}
	return c.(*net.UDPConn), info, nil
}

// DialerSocketOptions contains dialer-specific socket options.
type DialerSocketOptions struct {
	// SendBufferSize sets the send buffer size of the dialer.
	//
	// This is best-effort and does not return an error if the operation fails.
	//
	// Available on POSIX systems.
	SendBufferSize int

	// ReceiveBufferSize sets the receive buffer size of the dialer.
	//
	// This is best-effort and does not return an error if the operation fails.
	//
	// Available on POSIX systems.
	ReceiveBufferSize int

	// Fwmark sets the dialer's fwmark on Linux, or user cookie on FreeBSD.
	//
	// Available on Linux and FreeBSD.
	Fwmark int

	// TrafficClass sets the traffic class of the dialer.
	//
	// Available on most platforms except Windows.
	TrafficClass int

	// PathMTUDiscovery enables Path MTU Discovery on the dialer.
	//
	// Available on Linux, macOS, FreeBSD, and Windows.
	PathMTUDiscovery bool

	// ProbeUDPGSOSupport enables best-effort probing of
	// UDP Generic Segmentation Offload (GSO) support on the dialer.
	//
	// Available on Linux and Windows.
	ProbeUDPGSOSupport bool

	// UDPGenericReceiveOffload enables UDP Generic Receive Offload (GRO) on the dialer.
	//
	// Available on Linux and Windows.
	UDPGenericReceiveOffload bool
}

// Dialer returns a [Dialer] that sets the socket options.
func (dso DialerSocketOptions) Dialer() Dialer {
	return Dialer{
		fns: dso.buildSetFns(),
	}
}

var (
	// DefaultUDPDialerSocketOptions is the default [DialerSocketOptions] for UDP clients.
	DefaultUDPDialerSocketOptions = DialerSocketOptions{
		SendBufferSize:           DefaultUDPSocketBufferSize,
		ReceiveBufferSize:        DefaultUDPSocketBufferSize,
		PathMTUDiscovery:         true,
		ProbeUDPGSOSupport:       true,
		UDPGenericReceiveOffload: true,
	}

	// DefaultUDPDialer is the default [Dialer] for UDP clients.
	DefaultUDPDialer = DefaultUDPDialerSocketOptions.Dialer()
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

// DialerCache is a map of [DialerSocketOptions] to [Dialer].
type DialerCache map[DialerSocketOptions]Dialer

// NewDialerCache creates a new cache for [Dialer] with a few default entries.
func NewDialerCache() DialerCache {
	return DialerCache{
		DefaultUDPDialerSocketOptions: DefaultUDPDialer,
	}
}

// Get returns a [Dialer] for the given [DialerSocketOptions].
func (cache DialerCache) Get(dso DialerSocketOptions) (d Dialer) {
	d, ok := cache[dso]
	if ok {
		return
	}
	d = dso.Dialer()
	cache[dso] = d
	return
}

package conn

import (
	"context"
	"fmt"
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

// PMTUDMode is the Path MTU Discovery mode of a socket.
type PMTUDMode uint8

const (
	// PMTUDModeDefault is the default PMTUD mode of the socket.
	PMTUDModeDefault PMTUDMode = iota

	// PMTUDModeDont sets the socket to not perform Path MTU Discovery.
	//
	// DF is never set. Fragmentation happens both locally and on path.
	//
	//  - On Linux and Windows, this sets IP{,V6}_MTU_DISCOVER to IP_PMTUDISC_DONT.
	//  - On macOS and FreeBSD, this sets IP{,V6}_DONTFRAG to 0.
	//  - On other platforms, this is ignored.
	PMTUDModeDont

	// PMTUDModeDo sets the socket to always perform Path MTU Discovery.
	//
	// DF is always set. Fragmentation is disallowed.
	//
	//  - On Linux and Windows, this sets IP{,V6}_MTU_DISCOVER to IP_PMTUDISC_DO.
	//  - On macOS and FreeBSD, this sets IP{,V6}_DONTFRAG to 1.
	//  - On other platforms, this is ignored.
	PMTUDModeDo

	// PMTUDModeProbe is like [PMTUDModeDo], but permits sending packets larger than
	// the probed path MTU, with DF always set.
	//
	//  - On Linux and Windows, this sets IP{,V6}_MTU_DISCOVER to IP_PMTUDISC_PROBE.
	//  - On other platforms, this is ignored.
	PMTUDModeProbe

	// PMTUDModeWant sets IP_PMTUDISC_WANT on Linux.
	//
	// Fragmentation will happen locally if needed according to the path MTU,
	// otherwise the DF flag will be set.
	//
	// On other platforms, this is ignored.
	PMTUDModeWant

	// PMTUDModeInterface sets IP_PMTUDISC_INTERFACE on Linux.
	//
	// DF is never set. Fragmentation is disallowed locally. Ignore the path MTU and
	// always use the interface MTU.
	//
	// On other platforms, this is ignored.
	PMTUDModeInterface

	// PMTUDModeOmit sets IP_PMTUDISC_OMIT on Linux.
	//
	// This is a weaker version of [PMTUDModeInterface] that permits fragmentation if
	// interface MTU is exceeded.
	//
	// On other platforms, this is ignored.
	PMTUDModeOmit
)

// String returns its string representation.
func (m PMTUDMode) String() string {
	switch m {
	case PMTUDModeDefault:
		return "default"
	case PMTUDModeDont:
		return "dont"
	case PMTUDModeDo:
		return "do"
	case PMTUDModeProbe:
		return "probe"
	case PMTUDModeWant:
		return "want"
	case PMTUDModeInterface:
		return "interface"
	case PMTUDModeOmit:
		return "omit"
	default:
		return fmt.Sprintf("invalid(%d)", m)
	}
}

// AppendText implements [encoding.TextAppender].
func (m PMTUDMode) AppendText(b []byte) ([]byte, error) {
	switch m {
	case PMTUDModeDefault:
		return append(b, "default"...), nil
	case PMTUDModeDont:
		return append(b, "dont"...), nil
	case PMTUDModeDo:
		return append(b, "do"...), nil
	case PMTUDModeProbe:
		return append(b, "probe"...), nil
	case PMTUDModeWant:
		return append(b, "want"...), nil
	case PMTUDModeInterface:
		return append(b, "interface"...), nil
	case PMTUDModeOmit:
		return append(b, "omit"...), nil
	default:
		return b, fmt.Errorf("invalid PMTUDMode: %d", m)
	}
}

// MarshalText implements [encoding.TextMarshaler].
func (m PMTUDMode) MarshalText() ([]byte, error) {
	return m.AppendText(nil)
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (m *PMTUDMode) UnmarshalText(text []byte) error {
	switch string(text) {
	case "default", "":
		*m = PMTUDModeDefault
	case "dont":
		*m = PMTUDModeDont
	case "do":
		*m = PMTUDModeDo
	case "probe":
		*m = PMTUDModeProbe
	case "want":
		*m = PMTUDModeWant
	case "interface":
		*m = PMTUDModeInterface
	case "omit":
		*m = PMTUDModeOmit
	default:
		return fmt.Errorf("invalid PMTUDMode: %q", text)
	}
	return nil
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

	// PathMTUDiscovery sets the Path MTU Discovery mode of the socket.
	//
	// Available on Linux, macOS, FreeBSD, and Windows.
	PathMTUDiscovery PMTUDMode

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

// DefaultUDPSocketBufferSize is the default send and receive buffer sizes we set on UDP sockets.
//
//   - On Linux, the default is 4 MiB, which has been the default net.core.{r,w}mem_max since 6.18.
//     setsockopt(2) doubles it to 8 MiB. Higher values are silently clamped to net.core.{r,w}mem_max.
//   - On Windows, the default is 8 MiB. Windows allows setting socket buffer sizes to any int32 value.
//   - On macOS, the default is 8 MiB, which is the default kern.ipc.maxsockbuf.
//     SB_MAX_ADJUST was dropped in 2024, so the ~7 MiB cap no longer applies.
//     Higher values are silently clamped to kern.ipc.maxsockbuf.
//   - On FreeBSD, the default is 4 MiB, although sb_max_adj permits slightly above 7 MiB.
//     Setting any higher value returns -ENOBUFS.
//   - On OpenBSD, the default is 2 MiB, which is the default SB_MAX.
//     Setting any higher value returns -ENOBUFS.
//   - On DragonFly BSD, the default is 4 MiB, although it is silently clamped to sb_max_adj,
//     which is slightly below 512 KiB.
//   - On NetBSD, sb_max_adj is less than 256 KiB. Setting any value higher than that returns -ENOBUFS.
//     So we don't set a default.
//   - On other platforms, we don't know the behavior, so we don't set a default.
const DefaultUDPSocketBufferSize = defaultUDPSocketBufferSize

var (
	// DefaultUDPServerSocketOptions is the default [UDPSocketOptions] for UDP servers.
	DefaultUDPServerSocketOptions = UDPSocketOptions{
		SendBufferSize:           DefaultUDPSocketBufferSize,
		ReceiveBufferSize:        DefaultUDPSocketBufferSize,
		PathMTUDiscovery:         PMTUDModeDo,
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
		PathMTUDiscovery:         PMTUDModeDo,
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

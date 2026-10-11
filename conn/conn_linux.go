package conn

import (
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

const defaultUDPSocketBufferSize = 4 * 1024 * 1024

func setSendBufferSize(fd, size int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, size); err != nil {
		return fmt.Errorf("failed to set socket option SO_SNDBUF to %d: %w", size, err)
	}
	if !hasLargerDefaultMaxSocketBufferSize() {
		got, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
		if err != nil {
			return fmt.Errorf("failed to get socket option SO_SNDBUF: %w", err)
		}
		if got < size {
			_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, size)
		}
	}
	return nil
}

func setRecvBufferSize(fd, size int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, size); err != nil {
		return fmt.Errorf("failed to set socket option SO_RCVBUF to %d: %w", size, err)
	}
	if !hasLargerDefaultMaxSocketBufferSize() {
		got, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
		if err != nil {
			return fmt.Errorf("failed to get socket option SO_RCVBUF: %w", err)
		}
		if got < size {
			_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, size)
		}
	}
	return nil
}

var hasLargerDefaultMaxSocketBufferSize = sync.OnceValue(func() bool {
	// https://github.com/torvalds/linux/commit/a6d4f25888b83b8300aef28d9ee22765c1cc9b34
	// raised the default net.core.{r,w}mem_max to 4 MiB.
	return kernelVersionGE(6, 18)
})

func kernelVersionGE(major, minor int) bool {
	kMajor, kMinor := kernelVersion()
	return kMajor > major || (kMajor == major && kMinor >= minor)
}

var kernelVersion = sync.OnceValues(func() (major, minor int) {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return 0, 0
	}
	return parseUtsnameRelease(uname.Release)
})

func parseUtsnameRelease(release [65]byte) (major, minor int) {
	var (
		n       int
		isMinor bool
	)
	for _, c := range release {
		switch {
		case '0' <= c && c <= '9':
			n = (n * 10) + int(c-'0')
		case c == '.':
			if isMinor {
				return major, n
			}
			isMinor = true
			major = n
			n = 0
		default:
			return 0, 0
		}
	}
	return 0, 0
}

func setFwmark(fd, fwmark int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, fwmark); err != nil {
		return fmt.Errorf("failed to set socket option SO_MARK: %w", err)
	}
	return nil
}

func setTrafficClass(fd int, network string, trafficClass int) error {
	// Set IP_TOS for both v4 and v6.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TOS, trafficClass); err != nil {
		return fmt.Errorf("failed to set socket option IP_TOS: %w", err)
	}

	switch network {
	case "tcp4", "udp4":
	case "tcp6", "udp6":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, trafficClass); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_TCLASS: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}

	return nil
}

func (fns setFuncSlice) appendSetPMTUDFunc(pmtud PMTUDMode) setFuncSlice {
	var value int
	switch pmtud {
	case PMTUDModeDont:
		value = unix.IP_PMTUDISC_DONT
	case PMTUDModeDo:
		value = unix.IP_PMTUDISC_DO
	case PMTUDModeProbe:
		value = unix.IP_PMTUDISC_PROBE
	case PMTUDModeWant:
		value = unix.IP_PMTUDISC_WANT
	case PMTUDModeInterface:
		value = unix.IP_PMTUDISC_INTERFACE
	case PMTUDModeOmit:
		value = unix.IP_PMTUDISC_OMIT
	default:
		return fns
	}
	return append(fns, func(fd int, network string, _ *SocketInfo) error {
		return setPMTUD(fd, network, value)
	})
}

func setPMTUD(fd int, network string, value int) error {
	// Set IP_MTU_DISCOVER for both v4 and v6.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, value); err != nil {
		return fmt.Errorf("failed to set socket option IP_MTU_DISCOVER to %d: %w", value, err)
	}

	switch network {
	case "tcp4", "udp4":
	case "tcp6", "udp6":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, value); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_MTU_DISCOVER to %d: %w", value, err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}

	return nil
}

func probeUDPGSOSupport(fd int, info *SocketInfo) {
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_UDP, unix.UDP_SEGMENT, 0); err == nil {
		// UDP_MAX_SEGMENTS as defined in linux/udp.h was originally 64.
		// It got bumped to 128 in Linux 6.9: https://github.com/torvalds/linux/commit/1382e3b6a3500c245e5278c66d210c02926f804f
		// The receive path still only supports 64 segments, so 64 it is.
		info.MaxUDPGSOSegments = 64
	}
}

func setUDPGenericReceiveOffload(fd int, info *SocketInfo) {
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_UDP, unix.UDP_GRO, 1); err == nil {
		info.UDPGenericReceiveOffload = true
	}
}

func setRecvPktinfo(fd int, network string) error {
	switch network {
	case "udp4":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_PKTINFO, 1); err != nil {
			return fmt.Errorf("failed to set socket option IP_PKTINFO: %w", err)
		}
	case "udp6":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_RECVPKTINFO: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}
	return nil
}

func (opts UDPSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(opts.SendBufferSize).
		appendSetRecvBufferSize(opts.ReceiveBufferSize).
		appendSetFwmarkFunc(opts.Fwmark).
		appendSetTrafficClassFunc(opts.TrafficClass).
		appendSetPMTUDFunc(opts.PathMTUDiscovery).
		appendProbeUDPGSOSupportFunc(opts.ProbeUDPGSOSupport).
		appendSetUDPGenericReceiveOffloadFunc(opts.UDPGenericReceiveOffload).
		appendSetRecvPktinfoFunc(opts.ReceivePacketInfo)
}

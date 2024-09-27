package conn

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func setSendBufferSize(fd, size int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, size); err != nil {
		return fmt.Errorf("failed to set socket option SO_SNDBUF: %w", err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, size)
	return nil
}

func setRecvBufferSize(fd, size int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, size); err != nil {
		return fmt.Errorf("failed to set socket option SO_RCVBUF: %w", err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, size)
	return nil
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

func setPMTUD(fd int, network string) error {
	// Set IP_MTU_DISCOVER for both v4 and v6.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
		return fmt.Errorf("failed to set socket option IP_MTU_DISCOVER: %w", err)
	}

	switch network {
	case "tcp4", "udp4":
	case "tcp6", "udp6":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_MTU_DISCOVER: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}

	return nil
}

func setUDPGenericReceiveOffload(fd int) {
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_UDP, unix.UDP_GRO, 1)
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

func (lso ListenerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(lso.SendBufferSize).
		appendSetRecvBufferSize(lso.ReceiveBufferSize).
		appendSetFwmarkFunc(lso.Fwmark).
		appendSetTrafficClassFunc(lso.TrafficClass).
		appendSetPMTUDFunc(lso.PathMTUDiscovery).
		appendSetUDPGenericReceiveOffloadFunc(lso.UDPGenericReceiveOffload).
		appendSetRecvPktinfoFunc(lso.ReceivePacketInfo)
}

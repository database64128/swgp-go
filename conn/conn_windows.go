package conn

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func setSendBufferSize(fd, size int) error {
	if err := windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF, size); err != nil {
		return fmt.Errorf("failed to set socket option SO_SNDBUF: %w", err)
	}
	return nil
}

func setRecvBufferSize(fd, size int) error {
	if err := windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF, size); err != nil {
		return fmt.Errorf("failed to set socket option SO_RCVBUF: %w", err)
	}
	return nil
}

const (
	IP_MTU_DISCOVER   = 71
	IPV6_MTU_DISCOVER = 71
)

// enum PMTUD_STATE from ws2ipdef.h
const (
	IP_PMTUDISC_NOT_SET = iota
	IP_PMTUDISC_DO
	IP_PMTUDISC_DONT
	IP_PMTUDISC_PROBE
	IP_PMTUDISC_MAX
)

func setPMTUD(fd int, network string) error {
	// Set IP_MTU_DISCOVER for both v4 and v6.
	if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO); err != nil {
		return fmt.Errorf("failed to set socket option IP_MTU_DISCOVER: %w", err)
	}

	switch network {
	case "tcp4", "udp4":
	case "tcp6", "udp6":
		if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, IPV6_MTU_DISCOVER, IP_PMTUDISC_DO); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_MTU_DISCOVER: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}

	return nil
}

func setUDPGenericReceiveOffload(fd int, info *SocketInfo) {
	// Both quinn and msquic set this to 65535.
	if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_UDP, windows.UDP_RECV_MAX_COALESCED_SIZE, 65535); err == nil {
		info.UDPGenericReceiveOffload = true
	}
}

func setRecvPktinfo(fd int, network string) error {
	// Set IP_PKTINFO for both v4 and v6.
	if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_PKTINFO, 1); err != nil {
		return fmt.Errorf("failed to set socket option IP_PKTINFO: %w", err)
	}

	switch network {
	case "udp4":
	case "udp6":
		if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_PKTINFO, 1); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_PKTINFO: %w", err)
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
		appendSetPMTUDFunc(lso.PathMTUDiscovery).
		appendSetUDPGenericReceiveOffloadFunc(lso.UDPGenericReceiveOffload).
		appendSetRecvPktinfoFunc(lso.ReceivePacketInfo)
}

//go:build dragonfly || freebsd || netbsd || openbsd

package conn

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func setRecvPktinfo(fd int, network string) error {
	switch network {
	case "udp4":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVDSTADDR, 1); err != nil {
			return fmt.Errorf("failed to set socket option IP_RECVDSTADDR: %w", err)
		}
		// These BSDs have IP_RECVIF, but it cannot be used when sending.
	case "udp6":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_RECVPKTINFO: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}
	return nil
}

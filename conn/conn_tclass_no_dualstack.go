//go:build aix || darwin || dragonfly || freebsd || netbsd || openbsd || solaris || zos

package conn

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func setTrafficClass(fd int, network string, trafficClass int) error {
	switch network {
	case "tcp4", "udp4":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TOS, trafficClass); err != nil {
			return fmt.Errorf("failed to set socket option IP_TOS: %w", err)
		}
	case "tcp6", "udp6":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, trafficClass); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_TCLASS: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}
	return nil
}

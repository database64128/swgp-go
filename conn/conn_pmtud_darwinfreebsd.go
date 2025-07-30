//go:build darwin || freebsd

package conn

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func setPMTUD(fd int, network string) error {
	switch network {
	case "udp4":
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1); err != nil {
			return fmt.Errorf("failed to set socket option IP_DONTFRAG: %w", err)
		}
	case "udp6":
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_DONTFRAG: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}
	return nil
}

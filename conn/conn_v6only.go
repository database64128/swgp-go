//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || zos

package conn

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func getIPv6Only(fd int, network string, info *SocketInfo) error {
	switch network {
	case "tcp6", "udp6":
		v6only, err := unix.GetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY)
		if err != nil {
			return fmt.Errorf("failed to get socket option IPV6_V6ONLY: %w", err)
		}
		info.IPv6Only = v6only != 0
	}
	return nil
}

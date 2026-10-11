//go:build aix || darwin || dragonfly || freebsd || netbsd || openbsd || solaris || zos

package conn

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func setSendBufferSize(fd, size int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, size); err != nil {
		return fmt.Errorf("failed to set socket option SO_SNDBUF to %d: %w", size, err)
	}
	return nil
}

func setRecvBufferSize(fd, size int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, size); err != nil {
		return fmt.Errorf("failed to set socket option SO_RCVBUF to %d: %w", size, err)
	}
	return nil
}

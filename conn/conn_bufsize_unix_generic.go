//go:build unix && !linux

package conn

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func setSendBufferSize(fd, size int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, size); err != nil {
		return fmt.Errorf("failed to set socket option SO_SNDBUF: %w", err)
	}
	return nil
}

func setRecvBufferSize(fd, size int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, size); err != nil {
		return fmt.Errorf("failed to set socket option SO_RCVBUF: %w", err)
	}
	return nil
}

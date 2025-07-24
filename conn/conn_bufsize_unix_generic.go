//go:build aix || darwin || dragonfly || freebsd || netbsd || openbsd || solaris || zos

package conn

import (
	"golang.org/x/sys/unix"
)

func setSendBufferSize(fd, size int) error {
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, size)
	return nil
}

func setRecvBufferSize(fd, size int) error {
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, size)
	return nil
}

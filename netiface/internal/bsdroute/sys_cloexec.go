//go:build darwin

package bsdroute

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func newRoutingSocket() (int, error) {
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return 0, os.NewSyscallError("socket", err)
	}

	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return 0, os.NewSyscallError("setnonblock", err)
	}

	return fd, nil
}

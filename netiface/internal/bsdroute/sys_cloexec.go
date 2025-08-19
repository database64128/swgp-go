//go:build darwin

package bsdroute

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func Socket(domain int, typ int, proto int) (fd int, err error) {
	syscall.ForkLock.RLock()
	fd, err = unix.Socket(domain, typ, proto)
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

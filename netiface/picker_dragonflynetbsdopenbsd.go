//go:build dragonfly || netbsd || openbsd

package netiface

import (
	"os"

	"golang.org/x/sys/unix"
)

func newRoutingSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.AF_UNSPEC)
	if err != nil {
		return 0, os.NewSyscallError("socket", err)
	}
	return fd, nil
}

//go:build linux || netbsd

package conn

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func mmsgSyscall(trap uintptr, fd int, msgvec []Mmsghdr, flags int) (int, syscall.Errno) {
	r0, _, e1 := unix.Syscall6(trap, uintptr(fd), uintptr(unsafe.Pointer(unsafe.SliceData(msgvec))), uintptr(len(msgvec)), uintptr(flags), 0, 0)
	if e1 != 0 {
		return 0, e1
	}
	return int(r0), 0
}

func recvmmsg(fd int, msgvec []Mmsghdr, flags int) (int, syscall.Errno) {
	return mmsgSyscall(SYS_RECVMMSG, fd, msgvec, flags)
}

func sendmmsg(fd int, msgvec []Mmsghdr, flags int) (int, syscall.Errno) {
	return mmsgSyscall(unix.SYS_SENDMMSG, fd, msgvec, flags)
}

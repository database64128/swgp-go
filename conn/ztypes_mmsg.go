//go:build linux || netbsd

package conn

import "golang.org/x/sys/unix"

type Mmsghdr struct {
	Msghdr unix.Msghdr
	Msglen uint32
}

//go:build linux && (386 || arm || mips || mipsle || ppc)

package conn

import "golang.org/x/sys/unix"

const SYS_RECVMMSG = unix.SYS_RECVMMSG_TIME64

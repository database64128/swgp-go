package conn

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func setFwmark(fd, fwmark int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_USER_COOKIE, fwmark); err != nil {
		return fmt.Errorf("failed to set socket option SO_MARK: %w", err)
	}
	return nil
}

func (lso ListenerSocketOptions) buildSetFns() setFuncSlice {
	// a buffer size(1 MiB) that fits nicely with the default limit of the sysctl
	// option kern.ipc.maxsockbuf(2 MiB) in FreeBSD
	const bufSize = 1 << 20

	return setFuncSlice{}.
		appendSetSendBufferSize(bufSize).
		appendSetRecvBufferSize(bufSize).
		appendSetFwmarkFunc(lso.Fwmark).
		appendSetTrafficClassFunc(lso.TrafficClass).
		appendSetPMTUDFunc(lso.PathMTUDiscovery)
}

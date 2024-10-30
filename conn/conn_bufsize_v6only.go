//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || windows || zos

package conn

func (fns setFuncSlice) appendGetIPv6Only() setFuncSlice {
	return append(fns, getIPv6Only)
}

func (fns setFuncSlice) appendSetSendBufferSize(size int) setFuncSlice {
	if size > 0 {
		return append(fns, func(fd int, _ string, _ *SocketInfo) error {
			return setSendBufferSize(fd, size)
		})
	}
	return fns
}

func (fns setFuncSlice) appendSetRecvBufferSize(size int) setFuncSlice {
	if size > 0 {
		return append(fns, func(fd int, _ string, _ *SocketInfo) error {
			return setRecvBufferSize(fd, size)
		})
	}
	return fns
}

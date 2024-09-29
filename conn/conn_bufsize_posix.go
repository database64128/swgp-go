//go:build unix || windows

package conn

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

//go:build linux || windows

package conn

func (fns setFuncSlice) appendSetUDPGenericReceiveOffloadFunc(gro bool) setFuncSlice {
	if gro {
		return append(fns, func(fd int, _ string, info *SocketInfo) error {
			setUDPGenericReceiveOffload(fd, info)
			return nil
		})
	}
	return fns
}

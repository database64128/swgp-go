//go:build linux || windows

package conn

func (fns setFuncSlice) appendProbeUDPGSOSupportFunc(probeUDPGSO bool) setFuncSlice {
	if probeUDPGSO {
		return append(fns, func(fd int, _ string, info *SocketInfo) error {
			probeUDPGSOSupport(fd, info)
			return nil
		})
	}
	return fns
}

func (fns setFuncSlice) appendSetUDPGenericReceiveOffloadFunc(gro bool) setFuncSlice {
	if gro {
		return append(fns, func(fd int, _ string, info *SocketInfo) error {
			setUDPGenericReceiveOffload(fd, info)
			return nil
		})
	}
	return fns
}

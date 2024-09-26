//go:build linux || windows

package conn

func (fns setFuncSlice) appendSetUDPGenericReceiveOffloadFunc(gro bool) setFuncSlice {
	if gro {
		return append(fns, func(fd int, _ string) error {
			setUDPGenericReceiveOffload(fd)
			return nil
		})
	}
	return fns
}

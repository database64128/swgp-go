//go:build darwin || freebsd || linux || windows

package conn

func (fns setFuncSlice) appendSetPMTUDFunc(pmtud bool) setFuncSlice {
	if pmtud {
		return append(fns, func(fd int, network string, _ *SocketInfo) error {
			return setPMTUD(fd, network)
		})
	}
	return fns
}

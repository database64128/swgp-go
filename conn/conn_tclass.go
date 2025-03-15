//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || zos

package conn

func (fns setFuncSlice) appendSetTrafficClassFunc(trafficClass int) setFuncSlice {
	if trafficClass != 0 {
		return append(fns, func(fd int, network string, _ *SocketInfo) error {
			return setTrafficClass(fd, network, trafficClass)
		})
	}
	return fns
}

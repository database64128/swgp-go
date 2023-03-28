//go:build aix || dragonfly || netbsd || openbsd || solaris || zos

package conn

func (lso ListenerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.appendSetTrafficClassFunc(lso.TrafficClass)
}

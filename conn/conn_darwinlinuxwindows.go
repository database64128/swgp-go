//go:build darwin || linux || windows

package conn

func (fns setFuncSlice) appendSetRecvPktinfoFunc(recvPktinfo bool) setFuncSlice {
	if recvPktinfo {
		return append(fns, setRecvPktinfo)
	}
	return fns
}

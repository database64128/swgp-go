//go:build darwin || freebsd || linux || windows

package conn

func (fns setFuncSlice) appendSetPMTUDFunc(pmtud bool) setFuncSlice {
	if pmtud {
		return append(fns, setPMTUD)
	}
	return fns
}

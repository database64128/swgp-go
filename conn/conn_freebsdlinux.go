//go:build freebsd || linux

package conn

func (fns setFuncSlice) appendSetFwmarkFunc(fwmark int) setFuncSlice {
	if fwmark != 0 {
		return append(fns, func(fd int, network string) error {
			return setFwmark(fd, fwmark)
		})
	}
	return fns
}

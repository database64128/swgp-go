//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows && !zos

package conn

func (UDPSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}
}

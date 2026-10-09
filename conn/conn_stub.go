//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows && !zos

package conn

const defaultUDPSocketBufferSize = 0

func (UDPSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}
}

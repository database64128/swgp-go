//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || windows || zos

package conn

func (fns setFuncSlice) appendSetRecvPktinfoFunc(recvPktinfo bool) setFuncSlice {
	if recvPktinfo {
		return append(fns, func(fd int, network string, _ *SocketInfo) error {
			// linux: IP_PKTINFO + IPV6_RECVPKTINFO
			// darwin, solaris, zos: IP_RECVPKTINFO + IPV6_RECVPKTINFO
			// freebsd, dragonfly, netbsd, openbsd: IP_RECVDSTADDR + IPV6_PKTINFO
			// windows: IP_PKTINFO + IPV6_PKTINFO
			return setRecvPktinfo(fd, network)
		})
	}
	return fns
}

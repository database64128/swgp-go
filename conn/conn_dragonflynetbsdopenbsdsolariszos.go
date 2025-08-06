//go:build dragonfly || netbsd || openbsd || solaris || zos

package conn

func (opts UDPSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(opts.SendBufferSize).
		appendSetRecvBufferSize(opts.ReceiveBufferSize).
		appendSetTrafficClassFunc(opts.TrafficClass).
		appendSetRecvPktinfoFunc(opts.ReceivePacketInfo)
}

package conn

const defaultUDPSocketBufferSize = 8 * 1024 * 1024

func (opts UDPSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(opts.SendBufferSize).
		appendSetRecvBufferSize(opts.ReceiveBufferSize).
		appendSetTrafficClassFunc(opts.TrafficClass).
		appendSetPMTUDFunc(opts.PathMTUDiscovery).
		appendSetRecvPktinfoFunc(opts.ReceivePacketInfo)
}

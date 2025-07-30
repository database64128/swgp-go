package conn

func (lso ListenerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(lso.SendBufferSize).
		appendSetRecvBufferSize(lso.ReceiveBufferSize).
		appendSetTrafficClassFunc(lso.TrafficClass).
		appendSetPMTUDFunc(lso.PathMTUDiscovery).
		appendSetRecvPktinfoFunc(lso.ReceivePacketInfo)
}

func (dso DialerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetSendBufferSize(dso.SendBufferSize).
		appendSetRecvBufferSize(dso.ReceiveBufferSize).
		appendSetTrafficClassFunc(dso.TrafficClass).
		appendSetPMTUDFunc(dso.PathMTUDiscovery)
}

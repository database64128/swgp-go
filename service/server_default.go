//go:build !linux

package service

func (s *server) setRecvAndRelayFunctions() {
	s.recvFromProxyConn = s.recvFromProxyConnGeneric
	s.relayProxyToWg = s.relayProxyToWgGeneric
	s.relayWgToProxy = s.relayWgToProxyGeneric
}

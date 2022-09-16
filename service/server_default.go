//go:build !linux

package service

func (s *server) setRelayFunc() {
	s.recvFromProxyConn = s.recvFromProxyConnGeneric
}

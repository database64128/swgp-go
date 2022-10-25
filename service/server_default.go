//go:build !linux

package service

func (s *server) setRelayFunc(batchMode string) {
	s.recvFromProxyConn = s.recvFromProxyConnGeneric
}

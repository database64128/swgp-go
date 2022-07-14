//go:build !linux

package service

func (s *server) setRelayProxyToWgFunc() {
	s.relayProxyToWg = s.relayProxyToWgGeneric
}

func (s *server) setRelayWgToProxyFunc() {
	s.relayWgToProxy = s.relayWgToProxyGeneric
}

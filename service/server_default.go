//go:build !linux

package service

import "net/netip"

func (s *server) getRelayProxyToWgFunc(batchMode string) func(clientAddr netip.AddrPort, natEntry *serverNatEntry) {
	return s.relayProxyToWgGeneric
}

func (s *server) getRelayWgToProxyFunc(batchMode string) func(clientAddr netip.AddrPort, natEntry *serverNatEntry) {
	return s.relayWgToProxyGeneric
}

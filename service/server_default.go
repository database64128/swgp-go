//go:build !linux

package service

import "net/netip"

func (s *server) getRelayProxyToWgFunc(disableSendmmsg bool) func(clientAddr netip.AddrPort, natEntry *serverNatEntry) {
	return s.relayProxyToWgGeneric
}

func (s *server) getRelayWgToProxyFunc(disableSendmmsg bool) func(clientAddr netip.AddrPort, natEntry *serverNatEntry) {
	return s.relayWgToProxyGeneric
}

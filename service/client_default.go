//go:build !linux

package service

import "net/netip"

func (c *client) getRelayWgToProxyFunc(batchMode string) func(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
	return c.relayWgToProxyGeneric
}

func (c *client) getRelayProxyToWgFunc(batchMode string) func(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
	return c.relayProxyToWgGeneric
}

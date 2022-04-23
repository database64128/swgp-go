//go:build !linux

package service

import "net/netip"

func (c *client) getRelayWgToProxyFunc(disableSendmmsg bool) func(clientAddr netip.AddrPort, natEntry *clientNatEntry) {
	return c.relayWgToProxyGeneric
}

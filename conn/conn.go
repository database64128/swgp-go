package conn

import (
	"net"
	"net/netip"
)

// ResolveAddrPort resolves a string representation of an address to a netip.AddrPort.
func ResolveAddrPort(address string) (addrPort netip.AddrPort, err error) {
	addrPort, err = netip.ParseAddrPort(address)
	if err != nil {
		var ua *net.UDPAddr
		ua, err = net.ResolveUDPAddr("udp", address)
		if err != nil {
			return
		}
		addrPort = ua.AddrPort()
	}
	return
}

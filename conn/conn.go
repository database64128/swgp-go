package conn

import (
	"net"
	"net/netip"
)

// Tov4Mappedv6 converts an IPv4 address to an IPv4-mapped IPv6 address.
// This function does nothing if addrPort is an IPv6 address.
func Tov4Mappedv6(addrPort netip.AddrPort) netip.AddrPort {
	if addrPort.Addr().Is4() {
		addr6 := addrPort.Addr().As16()
		ip := netip.AddrFrom16(addr6)
		port := addrPort.Port()
		return netip.AddrPortFrom(ip, port)
	}
	return addrPort
}

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

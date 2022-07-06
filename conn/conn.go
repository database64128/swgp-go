package conn

import "net/netip"

// Tov4Mappedv6 converts an IPv4 address to an IPv4-mapped IPv6 address.
// This function does nothing if addrPort is an IPv6 address.
//
// This is a workaround for https://github.com/golang/go/issues/52264.
func Tov4Mappedv6(addrPort netip.AddrPort) netip.AddrPort {
	if addrPort.Addr().Is4() {
		addr6 := addrPort.Addr().As16()
		ip := netip.AddrFrom16(addr6)
		port := addrPort.Port()
		return netip.AddrPortFrom(ip, port)
	}
	return addrPort
}

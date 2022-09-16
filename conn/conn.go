package conn

import (
	"net"
	"net/netip"
	"unsafe"
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

type addrPortHeader struct {
	ip   [16]byte
	z    unsafe.Pointer
	port uint16
}

// AddrPortMappedEqual returns whether the two addresses point to the same endpoint.
// An IPv4 address and an IPv4-mapped IPv6 address pointing to the same endpoint are considered equal.
// For example, 1.1.1.1:53 and [::ffff:1.1.1.1]:53 are considered equal.
func AddrPortMappedEqual(l, r netip.AddrPort) bool {
	lp := (*addrPortHeader)(unsafe.Pointer(&l))
	rp := (*addrPortHeader)(unsafe.Pointer(&r))
	return lp.ip == rp.ip && lp.port == rp.port
}

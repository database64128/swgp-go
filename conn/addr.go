package conn

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"unsafe"
)

// ResolveAddrPort resolves a host:port string into a [netip.AddrPort].
//
// If the host is a domain name, the first IP address returned by the resolver is used.
func ResolveAddrPort(address string) (netip.AddrPort, error) {
	addrPort, err := netip.ParseAddrPort(address)
	if err == nil {
		return addrPort, nil
	}

	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		return netip.AddrPort{}, err
	}

	portNumber, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("failed to parse port number: %w", err)
	}

	ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ips[0], uint16(portNumber)), nil
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

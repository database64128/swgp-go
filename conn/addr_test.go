package conn

import (
	"net/netip"
	"testing"
)

var (
	ip4addr     = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	ip4addrPort = netip.AddrPortFrom(ip4addr, 1080)
)

var (
	ip4in6addr     = netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1})
	ip4in6addrPort = netip.AddrPortFrom(ip4in6addr, 1080)
)

var (
	ip6addr     = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0xfa, 0xd6, 0x05, 0x72, 0xac, 0xbe, 0x71, 0x43, 0x14, 0xe5, 0x7a, 0x6e})
	ip6addrPort = netip.AddrPortFrom(ip6addr, 1080)
)

const (
	ip4addrString    = "127.0.0.1:1080"
	ip4in6addrString = "[::ffff:127.0.0.1]:1080"
	ip6addrString    = "[2001:db8:fad6:572:acbe:7143:14e5:7a6e]:1080"
)

func TestResolveAddrPort(t *testing.T) {
	addrPort, err := ResolveAddrPort(ip4addrString)
	if err != nil {
		t.Errorf("ResolveAddrPort(%q) failed: %v", ip4addrString, err)
	}
	if addrPort != ip4addrPort {
		t.Errorf("ResolveAddrPort(%q) = %v, want %v", ip4addrString, addrPort, ip4addrPort)
	}

	addrPort, err = ResolveAddrPort(ip4in6addrString)
	if err != nil {
		t.Errorf("ResolveAddrPort(%q) failed: %v", ip4in6addrString, err)
	}
	if addrPort != ip4in6addrPort {
		t.Errorf("ResolveAddrPort(%q) = %v, want %v", ip4in6addrString, addrPort, ip4in6addrPort)
	}

	addrPort, err = ResolveAddrPort(ip6addrString)
	if err != nil {
		t.Errorf("ResolveAddrPort(%q) failed: %v", ip6addrString, err)
	}
	if addrPort != ip6addrPort {
		t.Errorf("ResolveAddrPort(%q) = %v, want %v", ip6addrString, addrPort, ip6addrPort)
	}

	const domainPortString = "example.com:443"
	addrPort, err = ResolveAddrPort(domainPortString)
	if err != nil {
		t.Errorf("ResolveAddrPort(%q) failed: %v", domainPortString, err)
	}
	if !addrPort.Addr().IsValid() {
		t.Errorf("ResolveAddrPort(%q) returned invalid address", domainPortString)
	}
}

func TestAddrPortMappedEqual(t *testing.T) {
	if !AddrPortMappedEqual(ip4addrPort, ip4addrPort) {
		t.Errorf("AddrPortMappedEqual(%v, %v) = false, want true", ip4addrPort, ip4addrPort)
	}
	if !AddrPortMappedEqual(ip4addrPort, ip4in6addrPort) {
		t.Errorf("AddrPortMappedEqual(%v, %v) = false, want true", ip4addrPort, ip4in6addrPort)
	}
	if !AddrPortMappedEqual(ip4in6addrPort, ip4addrPort) {
		t.Errorf("AddrPortMappedEqual(%v, %v) = false, want true", ip4in6addrPort, ip4addrPort)
	}
	if !AddrPortMappedEqual(ip6addrPort, ip6addrPort) {
		t.Errorf("AddrPortMappedEqual(%v, %v) = false, want true", ip6addrPort, ip6addrPort)
	}
	if AddrPortMappedEqual(ip4addrPort, ip6addrPort) {
		t.Errorf("AddrPortMappedEqual(%v, %v) = true, want false", ip4addrPort, ip6addrPort)
	}
	if AddrPortMappedEqual(ip4in6addrPort, ip6addrPort) {
		t.Errorf("AddrPortMappedEqual(%v, %v) = true, want false", ip4in6addrPort, ip6addrPort)
	}
	if AddrPortMappedEqual(ip6addrPort, ip4addrPort) {
		t.Errorf("AddrPortMappedEqual(%v, %v) = true, want false", ip6addrPort, ip4addrPort)
	}
	if AddrPortMappedEqual(ip6addrPort, ip4in6addrPort) {
		t.Errorf("AddrPortMappedEqual(%v, %v) = true, want false", ip6addrPort, ip4in6addrPort)
	}

	ip4addrPort1 := netip.AddrPortFrom(ip4addr, 1081)
	if AddrPortMappedEqual(ip4addrPort, ip4addrPort1) {
		t.Errorf("AddrPortMappedEqual(%v, %v) = true, want false", ip4addrPort, ip4addrPort1)
	}
}

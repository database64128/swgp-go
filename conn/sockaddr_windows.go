package conn

import (
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/database64128/netx-go"
	"golang.org/x/sys/windows"
)

const (
	SizeofSockaddrInet4 = uint32(unsafe.Sizeof(windows.RawSockaddrInet4{}))
	SizeofSockaddrInet6 = uint32(unsafe.Sizeof(windows.RawSockaddrInet6{}))
)

func AddrPortToSockaddr(addrPort netip.AddrPort) (name *byte, namelen uint32) {
	switch {
	case !addrPort.IsValid():
		return nil, 0
	case addrPort.Addr().Is4():
		rsa4 := AddrPortToSockaddrInet4(addrPort)
		return (*byte)(unsafe.Pointer(&rsa4)), SizeofSockaddrInet4
	default:
		rsa6 := AddrPortToSockaddrInet6(addrPort)
		return (*byte)(unsafe.Pointer(&rsa6)), SizeofSockaddrInet6
	}
}

func AddrPortToSockaddrInet4(addrPort netip.AddrPort) windows.RawSockaddrInet4 {
	addr := addrPort.Addr()
	port := addrPort.Port()
	rsa4 := windows.RawSockaddrInet4{
		Family: windows.AF_INET,
		Addr:   addr.As4(),
	}
	p := (*[2]byte)(unsafe.Pointer(&rsa4.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	return rsa4
}

func AddrPortToSockaddrInet6(addrPort netip.AddrPort) windows.RawSockaddrInet6 {
	addr := addrPort.Addr()
	port := addrPort.Port()
	rsa6 := windows.RawSockaddrInet6{
		Family:   windows.AF_INET6,
		Addr:     addr.As16(),
		Scope_id: uint32(netx.ZoneCache.Index(addr.Zone())),
	}
	p := (*[2]byte)(unsafe.Pointer(&rsa6.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	return rsa6
}

func SockaddrToAddrPort(name *byte, namelen uint32) (netip.AddrPort, error) {
	switch namelen {
	case 0:
		return netip.AddrPort{}, nil

	case SizeofSockaddrInet4:
		rsa4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(name))
		return SockaddrInet4ToAddrPort(rsa4), nil

	case SizeofSockaddrInet6:
		rsa6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(name))
		return SockaddrInet6ToAddrPort(rsa6), nil

	default:
		return netip.AddrPort{}, fmt.Errorf("bad sockaddr length: %d", namelen)
	}
}

func SockaddrInet4ToAddrPort(sa *windows.RawSockaddrInet4) netip.AddrPort {
	portp := (*[2]byte)(unsafe.Pointer(&sa.Port))
	port := uint16(portp[0])<<8 + uint16(portp[1])
	ip := netip.AddrFrom4(sa.Addr)
	return netip.AddrPortFrom(ip, port)
}

func SockaddrInet6ToAddrPort(sa *windows.RawSockaddrInet6) netip.AddrPort {
	portp := (*[2]byte)(unsafe.Pointer(&sa.Port))
	port := uint16(portp[0])<<8 + uint16(portp[1])
	ip := netip.AddrFrom16(sa.Addr).WithZone(netx.ZoneCache.Name(int(sa.Scope_id)))
	return netip.AddrPortFrom(ip, port)
}

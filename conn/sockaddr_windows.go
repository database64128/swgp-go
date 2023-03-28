package conn

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	SizeofSockaddrInet4 = uint32(unsafe.Sizeof(windows.RawSockaddrInet4{}))
	SizeofSockaddrInet6 = uint32(unsafe.Sizeof(windows.RawSockaddrInet6{}))
)

func AddrPortToSockaddr(addrPort netip.AddrPort) (name *byte, namelen uint32) {
	if addrPort.Addr().Is4() {
		rsa4 := AddrPortToSockaddrInet4(addrPort)
		name = (*byte)(unsafe.Pointer(&rsa4))
		namelen = SizeofSockaddrInet4
	} else {
		rsa6 := AddrPortToSockaddrInet6(addrPort)
		name = (*byte)(unsafe.Pointer(&rsa6))
		namelen = SizeofSockaddrInet6
	}
	return
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
		Family: windows.AF_INET6,
		Addr:   addr.As16(),
	}
	p := (*[2]byte)(unsafe.Pointer(&rsa6.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	return rsa6
}

func SockaddrToAddrPort(name *byte, namelen uint32) (netip.AddrPort, error) {
	switch namelen {
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
	ip := netip.AddrFrom16(sa.Addr)
	return netip.AddrPortFrom(ip, port)
}

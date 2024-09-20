//go:build aix || darwin || dragonfly || freebsd || netbsd || openbsd || zos

package conn

import (
	"net/netip"
	"unsafe"

	"github.com/database64128/netx-go"
	"golang.org/x/sys/unix"
)

func AddrPortToSockaddrInet4(addrPort netip.AddrPort) unix.RawSockaddrInet4 {
	addr := addrPort.Addr()
	port := addrPort.Port()
	rsa4 := unix.RawSockaddrInet4{
		Len:    unix.SizeofSockaddrInet4,
		Family: unix.AF_INET,
		Addr:   addr.As4(),
	}
	p := (*[2]byte)(unsafe.Pointer(&rsa4.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	return rsa4
}

func AddrPortToSockaddrInet6(addrPort netip.AddrPort) unix.RawSockaddrInet6 {
	addr := addrPort.Addr()
	port := addrPort.Port()
	rsa6 := unix.RawSockaddrInet6{
		Len:      unix.SizeofSockaddrInet6,
		Family:   unix.AF_INET6,
		Addr:     addr.As16(),
		Scope_id: uint32(netx.ZoneCache.Index(addr.Zone())),
	}
	p := (*[2]byte)(unsafe.Pointer(&rsa6.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	return rsa6
}

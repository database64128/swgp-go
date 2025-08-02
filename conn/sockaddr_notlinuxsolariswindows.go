//go:build aix || darwin || dragonfly || freebsd || netbsd || openbsd || zos

package conn

import (
	"net/netip"
	"unsafe"

	"github.com/database64128/netx-go"
	"golang.org/x/sys/unix"
)

func SockaddrInet4PutAddrPort(sa *unix.RawSockaddrInet4, addrPort netip.AddrPort) {
	sa.Len = unix.SizeofSockaddrInet4
	sa.Family = unix.AF_INET
	port := addrPort.Port()
	p := (*[2]byte)(unsafe.Pointer(&sa.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	sa.Addr = addrPort.Addr().As4()
}

func SockaddrInet6PutAddrPort(sa *unix.RawSockaddrInet6, addrPort netip.AddrPort) {
	sa.Len = unix.SizeofSockaddrInet6
	sa.Family = unix.AF_INET6
	port := addrPort.Port()
	p := (*[2]byte)(unsafe.Pointer(&sa.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	addr := addrPort.Addr()
	sa.Addr = addr.As16()
	sa.Scope_id = uint32(netx.ZoneCache.Index(addr.Zone()))
}

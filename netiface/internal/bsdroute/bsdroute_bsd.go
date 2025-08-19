//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package bsdroute

import (
	"os"
	"slices"
	"unsafe"

	"golang.org/x/sys/unix"
)

// OpenRoutingSocket opens a new routing socket.
func OpenRoutingSocket() (*os.File, error) {
	fd, err := Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "route"), nil
}

// SysctlGetBytes retrieves system information for the given MIB.
func SysctlGetBytes(mib []int32) (b []byte, err error) {
	for {
		var n uintptr
		if err := sysctl(mib, nil, &n, nil, 0); err != nil {
			return nil, os.NewSyscallError("sysctl", err)
		}
		b = slices.Grow(b, int(n))
		n = uintptr(cap(b))
		if err := sysctl(mib, unsafe.SliceData(b), &n, nil, 0); err != nil {
			if err == unix.ENOMEM {
				continue
			}
			return nil, os.NewSyscallError("sysctl", err)
		}
		return b[:n], nil
	}
}

//go:linkname sysctl syscall.sysctl
//go:noescape
func sysctl(mib []int32, old *byte, oldlen *uintptr, new *byte, newlen uintptr) (err error)

const SizeofMsghdr = sizeofMsghdr

type Msghdr = msghdr

type MsgType uint8

func (m MsgType) String() string {
	return m.string()
}

type RouteFlags int32

func (f RouteFlags) AppendText(b []byte) ([]byte, error) {
	for _, flag := range routeFlagNames {
		if f&flag.mask != 0 {
			b = append(b, flag.name)
		}
	}
	return b, nil
}

func (f RouteFlags) MarshalText() ([]byte, error) {
	return f.AppendText(make([]byte, 0, len(routeFlagNames)))
}

type IfaceFlags int32

func (f IfaceFlags) AppendText(b []byte) ([]byte, error) {
	bLen := len(b)
	for _, flag := range ifaceFlagNames {
		if f&flag.mask != 0 {
			b = append(b, flag.name...)
			b = append(b, ',')
		}
	}
	if len(b) > bLen {
		b = b[:len(b)-1]
	}
	return b, nil
}

func (f IfaceFlags) MarshalText() ([]byte, error) {
	return f.AppendText(nil)
}

// Constants for interface IPv6 address flags (ifru_flags6).
// They share the same values across supported BSD variants.
//
//   - macOS: https://github.com/apple-oss-distributions/xnu/blob/94d3b452840153a99b38a3a9659680b2a006908e/bsd/netinet6/in6_var.h#L785-L821
//   - DragonFly BSD: https://github.com/DragonFlyBSD/DragonFlyBSD/blob/ba1276acd1c8c22d225b1bcf370a14c878644f44/sys/netinet6/in6_var.h#L457-L472
//   - FreeBSD: https://github.com/freebsd/freebsd-src/blob/7bbcbd43c53b49360969ca82b152fd6d971e9055/sys/netinet6/in6_var.h#L492-L505
//   - NetBSD: https://github.com/NetBSD/src/blob/2b3021f92cac3b692b6b23305b68f7bb4212bffd/sys/netinet6/in6_var.h#L400-L417
//   - OpenBSD: https://github.com/openbsd/src/blob/c0b7aa147b16eeebb8c9dc6debf303af3c74b7d5/sys/netinet6/in6_var.h#L287-L293
const (
	IN6_IFF_DEPRECATED = 0x10
	IN6_IFF_TEMPORARY  = 0x80
)

type inet6Ifreq struct {
	Name [unix.IFNAMSIZ]byte
	Ifru [68]int32
}

// IoctlGetIfaFlagInet6 calls ioctl(SIOCGIFAFLAG_IN6) on f to retrieve the interface IPv6 address flags for sa.
func IoctlGetIfaFlagInet6(fd int, name string, sa *unix.RawSockaddrInet6) (flags int32, err error) {
	const SIOCGIFAFLAG_IN6 = 0xc1206949
	var ifr inet6Ifreq
	_ = copy(ifr.Name[:], name)
	*(*unix.RawSockaddrInet6)(unsafe.Pointer(&ifr.Ifru)) = *sa
	if err := ioctlPtr(fd, SIOCGIFAFLAG_IN6, unsafe.Pointer(&ifr)); err != nil {
		return 0, os.NewSyscallError("ioctl", err)
	}
	return ifr.Ifru[0], nil
}

//go:linkname ioctlPtr syscall.ioctlPtr
//go:noescape
func ioctlPtr(fd int, req uint, arg unsafe.Pointer) (err error)

// ParseAddrs populates dst with pointers to the sockaddr structures in b as indicated by addrs.
func ParseAddrs(dst *[unix.RTAX_MAX]*unix.RawSockaddr, b []byte, addrs int32) {
	for i := range unix.RTAX_MAX {
		if addrs&(1<<i) == 0 {
			continue
		}
		// Yes, there will be shorter or even empty addresses.
		// route(4) prints them as "default".
		if len(b) >= unix.SizeofSockaddrInet4 {
			dst[i] = (*unix.RawSockaddr)(unsafe.Pointer(unsafe.SliceData(b)))
		}
		if len(b) == 0 {
			return
		}
		alignedLen := RtaAlign(b[0])
		if len(b) < int(alignedLen) {
			return
		}
		b = b[alignedLen:]
	}
}

// RtaAlign returns the size of a sockaddr when passed through a routing socket.
// It rounds up sa_len to a multiple of rtaAlignTo, with a minimum of rtaAlignTo.
//
// This is based on the {RT_}ROUNDUP macro found in various BSD source trees.
func RtaAlign(n uint8) uint8 {
	if n == 0 {
		return rtaAlignTo
	}
	return (n + rtaAlignTo - 1) & ^uint8(rtaAlignTo-1)
}

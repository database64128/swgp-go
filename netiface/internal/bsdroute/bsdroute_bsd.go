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

type IfaFlags6 int32

func (f IfaFlags6) AppendText(b []byte) ([]byte, error) {
	bLen := len(b)
	for _, flag := range ifaFlags6Names {
		if f&flag.mask != 0 {
			b = append(b, flag.name...)
			b = append(b, ' ')
		}
	}
	if len(b) > bLen {
		b = b[:len(b)-1]
	}
	return b, nil
}

func (f IfaFlags6) MarshalText() ([]byte, error) {
	return f.AppendText(nil)
}

type inet6Ifreq struct {
	Name [unix.IFNAMSIZ]byte
	Ifru [272]byte
}

// IoctlGetIfaFlagInet6 calls ioctl(SIOCGIFAFLAG_IN6) on f to retrieve the interface IPv6 address flags for sa.
func IoctlGetIfaFlagInet6(fd int, name string, sa *unix.RawSockaddrInet6) (flags IfaFlags6, err error) {
	const SIOCGIFAFLAG_IN6 = 0xc1206949
	var ifr inet6Ifreq
	_ = copy(ifr.Name[:], name)
	*(*unix.RawSockaddrInet6)(unsafe.Pointer(&ifr.Ifru)) = *sa
	if err := ioctlPtr(fd, SIOCGIFAFLAG_IN6, unsafe.Pointer(&ifr)); err != nil {
		return 0, os.NewSyscallError("ioctl", err)
	}
	return *(*IfaFlags6)(unsafe.Pointer(&ifr.Ifru)), nil
}

//go:linkname ioctlPtr golang.org/x/sys/unix.ioctlPtr
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

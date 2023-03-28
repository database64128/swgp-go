//go:build darwin || linux

package conn

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// SocketControlMessageBufferSize specifies the buffer size for receiving socket control messages.
const SocketControlMessageBufferSize = unix.SizeofCmsghdr + (unix.SizeofInet6Pktinfo+unix.SizeofPtr-1) & ^(unix.SizeofPtr-1)

// ParsePktinfoCmsg parses a single socket control message of type IP_PKTINFO or IPV6_PKTINFO,
// and returns the IP address and index of the network interface the packet was received from,
// or an error.
//
// This function is only implemented for Linux, macOS and Windows. On other platforms, this is a no-op.
func ParsePktinfoCmsg(cmsg []byte) (netip.Addr, uint32, error) {
	if len(cmsg) < unix.SizeofCmsghdr {
		return netip.Addr{}, 0, fmt.Errorf("control message length %d is shorter than cmsghdr length", len(cmsg))
	}

	cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(&cmsg[0]))

	switch {
	case cmsghdr.Level == unix.IPPROTO_IP && cmsghdr.Type == unix.IP_PKTINFO && len(cmsg) >= unix.SizeofCmsghdr+unix.SizeofInet4Pktinfo:
		pktinfo := (*unix.Inet4Pktinfo)(unsafe.Pointer(&cmsg[unix.SizeofCmsghdr]))
		return netip.AddrFrom4(pktinfo.Spec_dst), uint32(pktinfo.Ifindex), nil

	case cmsghdr.Level == unix.IPPROTO_IPV6 && cmsghdr.Type == unix.IPV6_PKTINFO && len(cmsg) >= unix.SizeofCmsghdr+unix.SizeofInet6Pktinfo:
		pktinfo := (*unix.Inet6Pktinfo)(unsafe.Pointer(&cmsg[unix.SizeofCmsghdr]))
		return netip.AddrFrom16(pktinfo.Addr), pktinfo.Ifindex, nil

	default:
		return netip.Addr{}, 0, fmt.Errorf("unknown control message level %d type %d", cmsghdr.Level, cmsghdr.Type)
	}
}

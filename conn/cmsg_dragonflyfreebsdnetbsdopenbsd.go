//go:build dragonfly || freebsd || netbsd || openbsd

package conn

import (
	"fmt"
	"net/netip"
	"slices"
	"unsafe"

	"golang.org/x/sys/unix"
)

// aix has IPV6_PKTINFO, but x/sys/unix does not provide support for it.

// NetBSD has IP_PKTINFO, but x/sys/unix does not provide support for it.

const (
	socketControlMessageBufferSize = alignedSizeofCmsghdr + max(alignedSizeofInet4Addr, alignedSizeofInet6Pktinfo)

	alignedSizeofInet4Addr    = (sizeofInet4Addr + cmsgAlignTo - 1) & ^(cmsgAlignTo - 1)
	alignedSizeofInet6Pktinfo = (unix.SizeofInet6Pktinfo + cmsgAlignTo - 1) & ^(cmsgAlignTo - 1)

	sizeofInet4Addr = 4 // sizeof(struct in_addr)
)

func parseSocketControlMessage(cmsg []byte) (m SocketControlMessage, err error) {
	for len(cmsg) >= unix.SizeofCmsghdr {
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(unsafe.SliceData(cmsg)))
		msgSize := cmsgAlign(int(cmsghdr.Len))
		if cmsghdr.Len < unix.SizeofCmsghdr || msgSize > len(cmsg) {
			return m, fmt.Errorf("invalid control message length %d", cmsghdr.Len)
		}

		switch {
		case cmsghdr.Level == unix.IPPROTO_IP && cmsghdr.Type == unix.IP_RECVDSTADDR:
			if len(cmsg) < alignedSizeofCmsghdr+sizeofInet4Addr {
				return m, fmt.Errorf("invalid IP_RECVDSTADDR control message length %d", cmsghdr.Len)
			}
			addr := [sizeofInet4Addr]byte(cmsg[alignedSizeofCmsghdr:])
			m.PktinfoAddr = netip.AddrFrom4(addr)

		case cmsghdr.Level == unix.IPPROTO_IPV6 && cmsghdr.Type == unix.IPV6_PKTINFO:
			if len(cmsg) < alignedSizeofCmsghdr+unix.SizeofInet6Pktinfo {
				return m, fmt.Errorf("invalid IPV6_PKTINFO control message length %d", cmsghdr.Len)
			}
			var pktinfo unix.Inet6Pktinfo
			_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), unix.SizeofInet6Pktinfo), cmsg[alignedSizeofCmsghdr:])
			m.PktinfoAddr = netip.AddrFrom16(pktinfo.Addr)
			m.PktinfoIfindex = pktinfo.Ifindex
		}

		cmsg = cmsg[msgSize:]
	}

	return m, nil
}

func (m SocketControlMessage) appendTo(b []byte) []byte {
	switch {
	case m.PktinfoAddr.Is4():
		bLen := len(b)
		b = slices.Grow(b, alignedSizeofCmsghdr+alignedSizeofInet4Addr)[:bLen+alignedSizeofCmsghdr+alignedSizeofInet4Addr]
		msgBuf := b[bLen:]
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(unsafe.SliceData(msgBuf)))
		*cmsghdr = unix.Cmsghdr{
			Len:   alignedSizeofCmsghdr + sizeofInet4Addr,
			Level: unix.IPPROTO_IP,
			Type:  unix.IP_RECVDSTADDR,
		}
		addr := m.PktinfoAddr.As4()
		_ = copy(msgBuf[alignedSizeofCmsghdr:], addr[:])

	case m.PktinfoAddr.Is6():
		bLen := len(b)
		b = slices.Grow(b, alignedSizeofCmsghdr+alignedSizeofInet6Pktinfo)[:bLen+alignedSizeofCmsghdr+alignedSizeofInet6Pktinfo]
		msgBuf := b[bLen:]
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(unsafe.SliceData(msgBuf)))
		*cmsghdr = unix.Cmsghdr{
			Len:   alignedSizeofCmsghdr + unix.SizeofInet6Pktinfo,
			Level: unix.IPPROTO_IPV6,
			Type:  unix.IPV6_PKTINFO,
		}
		pktinfo := unix.Inet6Pktinfo{
			Addr:    m.PktinfoAddr.As16(),
			Ifindex: m.PktinfoIfindex,
		}
		_ = copy(msgBuf[alignedSizeofCmsghdr:], unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), unix.SizeofInet6Pktinfo))
	}

	return b
}

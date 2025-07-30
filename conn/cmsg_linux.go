package conn

import (
	"fmt"
	"net/netip"
	"slices"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux is the only platform where it asserts that:
//
//	sizeof(struct cmsghdr) == CMSG_ALIGN(sizeof(struct cmsghdr))
//
// Kernel code only ever uses sizeof(struct cmsghdr) directly.
//
// Here we follow that convention and use [unix.SizeofCmsghdr] directly.

const (
	socketControlMessageBufferSize = unix.SizeofCmsghdr + max(alignedSizeofInet4Pktinfo, alignedSizeofInet6Pktinfo) +
		unix.SizeofCmsghdr + max(alignedSizeofGSOSegmentSize, alignedSizeofGROSegmentSize)

	alignedSizeofInet4Pktinfo   = (unix.SizeofInet4Pktinfo + cmsgAlignTo - 1) & ^(cmsgAlignTo - 1)
	alignedSizeofInet6Pktinfo   = (unix.SizeofInet6Pktinfo + cmsgAlignTo - 1) & ^(cmsgAlignTo - 1)
	alignedSizeofGSOSegmentSize = (sizeofGSOSegmentSize + cmsgAlignTo - 1) & ^(cmsgAlignTo - 1)
	alignedSizeofGROSegmentSize = (sizeofGROSegmentSize + cmsgAlignTo - 1) & ^(cmsgAlignTo - 1)

	sizeofGSOSegmentSize = 2 // int(unsafe.Sizeof(uint16(0)))
	sizeofGROSegmentSize = 4 // int(unsafe.Sizeof(int32(0)))
)

func parseSocketControlMessage(cmsg []byte) (m SocketControlMessage, err error) {
	for len(cmsg) >= unix.SizeofCmsghdr {
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(unsafe.SliceData(cmsg)))
		msgSize := cmsgAlign(int(cmsghdr.Len))
		if cmsghdr.Len < unix.SizeofCmsghdr || msgSize > len(cmsg) {
			return m, fmt.Errorf("invalid control message length %d", cmsghdr.Len)
		}

		switch {
		case cmsghdr.Level == unix.IPPROTO_IP && cmsghdr.Type == unix.IP_PKTINFO:
			if len(cmsg) < unix.SizeofCmsghdr+unix.SizeofInet4Pktinfo {
				return m, fmt.Errorf("invalid IP_PKTINFO control message length %d", cmsghdr.Len)
			}
			var pktinfo unix.Inet4Pktinfo
			_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), unix.SizeofInet4Pktinfo), cmsg[unix.SizeofCmsghdr:])
			m.PktinfoAddr = netip.AddrFrom4(pktinfo.Spec_dst)
			m.PktinfoIfindex = uint32(pktinfo.Ifindex)

		case cmsghdr.Level == unix.IPPROTO_IPV6 && cmsghdr.Type == unix.IPV6_PKTINFO:
			if len(cmsg) < unix.SizeofCmsghdr+unix.SizeofInet6Pktinfo {
				return m, fmt.Errorf("invalid IPV6_PKTINFO control message length %d", cmsghdr.Len)
			}
			var pktinfo unix.Inet6Pktinfo
			_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), unix.SizeofInet6Pktinfo), cmsg[unix.SizeofCmsghdr:])
			m.PktinfoAddr = netip.AddrFrom16(pktinfo.Addr)
			m.PktinfoIfindex = pktinfo.Ifindex

		case cmsghdr.Level == unix.IPPROTO_UDP && cmsghdr.Type == unix.UDP_GRO:
			if len(cmsg) < unix.SizeofCmsghdr+sizeofGROSegmentSize {
				return m, fmt.Errorf("invalid UDP_GRO control message length %d", cmsghdr.Len)
			}
			_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&m.SegmentSize)), sizeofGROSegmentSize), cmsg[unix.SizeofCmsghdr:])
		}

		cmsg = cmsg[msgSize:]
	}

	return m, nil
}

func (m SocketControlMessage) appendTo(b []byte) []byte {
	switch {
	case m.PktinfoAddr.Is4():
		bLen := len(b)
		b = slices.Grow(b, unix.SizeofCmsghdr+alignedSizeofInet4Pktinfo)[:bLen+unix.SizeofCmsghdr+alignedSizeofInet4Pktinfo]
		msgBuf := b[bLen:]
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(unsafe.SliceData(msgBuf)))
		*cmsghdr = unix.Cmsghdr{
			Len:   unix.SizeofCmsghdr + unix.SizeofInet4Pktinfo,
			Level: unix.IPPROTO_IP,
			Type:  unix.IP_PKTINFO,
		}
		pktinfo := unix.Inet4Pktinfo{
			Ifindex:  int32(m.PktinfoIfindex),
			Spec_dst: m.PktinfoAddr.As4(),
		}
		_ = copy(msgBuf[unix.SizeofCmsghdr:], unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), unix.SizeofInet4Pktinfo))

	case m.PktinfoAddr.Is6():
		bLen := len(b)
		b = slices.Grow(b, unix.SizeofCmsghdr+alignedSizeofInet6Pktinfo)[:bLen+unix.SizeofCmsghdr+alignedSizeofInet6Pktinfo]
		msgBuf := b[bLen:]
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(unsafe.SliceData(msgBuf)))
		*cmsghdr = unix.Cmsghdr{
			Len:   unix.SizeofCmsghdr + unix.SizeofInet6Pktinfo,
			Level: unix.IPPROTO_IPV6,
			Type:  unix.IPV6_PKTINFO,
		}
		pktinfo := unix.Inet6Pktinfo{
			Addr:    m.PktinfoAddr.As16(),
			Ifindex: m.PktinfoIfindex,
		}
		_ = copy(msgBuf[unix.SizeofCmsghdr:], unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), unix.SizeofInet6Pktinfo))
	}

	if m.SegmentSize > 0 {
		bLen := len(b)
		b = slices.Grow(b, unix.SizeofCmsghdr+alignedSizeofGSOSegmentSize)[:bLen+unix.SizeofCmsghdr+alignedSizeofGSOSegmentSize]
		msgBuf := b[bLen:]
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(unsafe.SliceData(msgBuf)))
		*cmsghdr = unix.Cmsghdr{
			Len:   unix.SizeofCmsghdr + sizeofGSOSegmentSize,
			Level: unix.IPPROTO_UDP,
			Type:  unix.UDP_SEGMENT,
		}
		segmentSize := uint16(m.SegmentSize)
		_ = copy(msgBuf[unix.SizeofCmsghdr:], unsafe.Slice((*byte)(unsafe.Pointer(&segmentSize)), sizeofGSOSegmentSize))
	}

	return b
}

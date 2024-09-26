package conn

import (
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/database64128/swgp-go/slicehelper"
	"golang.org/x/sys/unix"
)

const socketControlMessageBufferSize = unix.SizeofCmsghdr + alignedSizeofInet6Pktinfo +
	unix.SizeofCmsghdr + alignedSizeofGROSegmentSize

const sizeofGROSegmentSize = int(unsafe.Sizeof(uint16(0)))

func cmsgAlign(n uint64) uint64 {
	return (n + unix.SizeofPtr - 1) & ^uint64(unix.SizeofPtr-1)
}

func parseSocketControlMessage(cmsg []byte) (m SocketControlMessage, err error) {
	for len(cmsg) >= unix.SizeofCmsghdr {
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(unsafe.SliceData(cmsg)))
		msgSize := cmsgAlign(cmsghdr.Len)
		if cmsghdr.Len < unix.SizeofCmsghdr || int(msgSize) > len(cmsg) {
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
			var segmentSize uint16
			_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&segmentSize)), sizeofGROSegmentSize), cmsg[unix.SizeofCmsghdr:])
			m.SegmentSize = uint32(segmentSize)
		}

		cmsg = cmsg[msgSize:]
	}

	return m, nil
}

const (
	alignedSizeofInet4Pktinfo   = (unix.SizeofInet4Pktinfo + unix.SizeofPtr - 1) & ^(unix.SizeofPtr - 1)
	alignedSizeofInet6Pktinfo   = (unix.SizeofInet6Pktinfo + unix.SizeofPtr - 1) & ^(unix.SizeofPtr - 1)
	alignedSizeofGROSegmentSize = (sizeofGROSegmentSize + unix.SizeofPtr - 1) & ^(unix.SizeofPtr - 1)
)

func (m SocketControlMessage) appendTo(b []byte) []byte {
	switch {
	case m.PktinfoAddr.Is4():
		var msgBuf []byte
		b, msgBuf = slicehelper.Extend(b, unix.SizeofCmsghdr+alignedSizeofInet4Pktinfo)
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
		var msgBuf []byte
		b, msgBuf = slicehelper.Extend(b, unix.SizeofCmsghdr+alignedSizeofInet6Pktinfo)
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
		var msgBuf []byte
		b, msgBuf = slicehelper.Extend(b, unix.SizeofCmsghdr+alignedSizeofGROSegmentSize)
		cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(unsafe.SliceData(msgBuf)))
		*cmsghdr = unix.Cmsghdr{
			Len:   unix.SizeofCmsghdr + uint64(sizeofGROSegmentSize),
			Level: unix.IPPROTO_UDP,
			Type:  unix.UDP_GRO,
		}
		segmentSize := uint16(m.SegmentSize)
		_ = copy(msgBuf[unix.SizeofCmsghdr:], unsafe.Slice((*byte)(unsafe.Pointer(&segmentSize)), sizeofGROSegmentSize))
	}

	return b
}

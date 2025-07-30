package conn

import (
	"fmt"
	"net/netip"
	"slices"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	socketControlMessageBufferSize = alignedSizeofCmsghdr + max(alignedSizeofInet4Pktinfo, alignedSizeofInet6Pktinfo) +
		alignedSizeofCmsghdr + max(alignedSizeofSendMsgSize, alignedSizeofCoalescedInfo)

	alignedSizeofCmsghdr       = (sizeofCmsghdr + cmsgAlignTo - 1) & ^(cmsgAlignTo - 1)
	alignedSizeofInet4Pktinfo  = (sizeofInet4Pktinfo + cmsgAlignTo - 1) & ^(cmsgAlignTo - 1)
	alignedSizeofInet6Pktinfo  = (sizeofInet6Pktinfo + cmsgAlignTo - 1) & ^(cmsgAlignTo - 1)
	alignedSizeofSendMsgSize   = (sizeofSendMsgSize + cmsgAlignTo - 1) & ^(cmsgAlignTo - 1)
	alignedSizeofCoalescedInfo = (sizeofCoalescedInfo + cmsgAlignTo - 1) & ^(cmsgAlignTo - 1)

	cmsgAlignTo         = int(unsafe.Sizeof(uintptr(0)))
	sizeofCmsghdr       = int(unsafe.Sizeof(windows.WSACMSGHDR{}))
	sizeofInet4Pktinfo  = int(unsafe.Sizeof(windows.IN_PKTINFO{}))
	sizeofInet6Pktinfo  = int(unsafe.Sizeof(windows.IN6_PKTINFO{}))
	sizeofSendMsgSize   = int(unsafe.Sizeof(uint32(0)))
	sizeofCoalescedInfo = int(unsafe.Sizeof(uint32(0)))
)

func parseSocketControlMessage(cmsg []byte) (m SocketControlMessage, err error) {
	for len(cmsg) >= sizeofCmsghdr {
		cmsghdr := (*windows.WSACMSGHDR)(unsafe.Pointer(unsafe.SliceData(cmsg)))
		msgLen := int(cmsghdr.Len)
		msgSize := cmsgAlign(msgLen)
		if msgLen < sizeofCmsghdr || msgSize > len(cmsg) {
			return m, fmt.Errorf("invalid control message length %d", cmsghdr.Len)
		}

		switch {
		case cmsghdr.Level == windows.IPPROTO_IP && cmsghdr.Type == windows.IP_PKTINFO:
			if len(cmsg) < alignedSizeofCmsghdr+sizeofInet4Pktinfo {
				return m, fmt.Errorf("invalid IP_PKTINFO control message length %d", cmsghdr.Len)
			}
			var pktinfo windows.IN_PKTINFO
			_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), sizeofInet4Pktinfo), cmsg[alignedSizeofCmsghdr:])
			m.PktinfoAddr = netip.AddrFrom4(pktinfo.Addr)
			m.PktinfoIfindex = pktinfo.Ifindex

		case cmsghdr.Level == windows.IPPROTO_IPV6 && cmsghdr.Type == windows.IPV6_PKTINFO:
			if len(cmsg) < alignedSizeofCmsghdr+sizeofInet6Pktinfo {
				return m, fmt.Errorf("invalid IPV6_PKTINFO control message length %d", cmsghdr.Len)
			}
			var pktinfo windows.IN6_PKTINFO
			_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), sizeofInet6Pktinfo), cmsg[alignedSizeofCmsghdr:])
			m.PktinfoAddr = netip.AddrFrom16(pktinfo.Addr)
			m.PktinfoIfindex = pktinfo.Ifindex

		case cmsghdr.Level == windows.IPPROTO_UDP && cmsghdr.Type == windows.UDP_COALESCED_INFO:
			if len(cmsg) < alignedSizeofCmsghdr+sizeofCoalescedInfo {
				return m, fmt.Errorf("invalid UDP_COALESCED_INFO control message length %d", cmsghdr.Len)
			}
			_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&m.SegmentSize)), sizeofCoalescedInfo), cmsg[alignedSizeofCmsghdr:])
		}

		cmsg = cmsg[msgSize:]
	}

	return m, nil
}

func (m SocketControlMessage) appendTo(b []byte) []byte {
	switch {
	case m.PktinfoAddr.Is4():
		bLen := len(b)
		b = slices.Grow(b, alignedSizeofCmsghdr+alignedSizeofInet4Pktinfo)[:bLen+alignedSizeofCmsghdr+alignedSizeofInet4Pktinfo]
		msgBuf := b[bLen:]
		cmsghdr := (*windows.WSACMSGHDR)(unsafe.Pointer(unsafe.SliceData(msgBuf)))
		*cmsghdr = windows.WSACMSGHDR{
			Len:   uintptr(alignedSizeofCmsghdr + sizeofInet4Pktinfo),
			Level: windows.IPPROTO_IP,
			Type:  windows.IP_PKTINFO,
		}
		pktinfo := windows.IN_PKTINFO{
			Addr:    m.PktinfoAddr.As4(),
			Ifindex: m.PktinfoIfindex,
		}
		_ = copy(msgBuf[alignedSizeofCmsghdr:], unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), sizeofInet4Pktinfo))

	case m.PktinfoAddr.Is6():
		bLen := len(b)
		b = slices.Grow(b, alignedSizeofCmsghdr+alignedSizeofInet6Pktinfo)[:bLen+alignedSizeofCmsghdr+alignedSizeofInet6Pktinfo]
		msgBuf := b[bLen:]
		cmsghdr := (*windows.WSACMSGHDR)(unsafe.Pointer(unsafe.SliceData(msgBuf)))
		*cmsghdr = windows.WSACMSGHDR{
			Len:   uintptr(alignedSizeofCmsghdr + sizeofInet6Pktinfo),
			Level: windows.IPPROTO_IPV6,
			Type:  windows.IPV6_PKTINFO,
		}
		pktinfo := windows.IN6_PKTINFO{
			Addr:    m.PktinfoAddr.As16(),
			Ifindex: m.PktinfoIfindex,
		}
		_ = copy(msgBuf[alignedSizeofCmsghdr:], unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), sizeofInet6Pktinfo))
	}

	if m.SegmentSize > 0 {
		bLen := len(b)
		b = slices.Grow(b, alignedSizeofCmsghdr+alignedSizeofSendMsgSize)[:bLen+alignedSizeofCmsghdr+alignedSizeofSendMsgSize]
		msgBuf := b[bLen:]
		cmsghdr := (*windows.WSACMSGHDR)(unsafe.Pointer(unsafe.SliceData(msgBuf)))
		*cmsghdr = windows.WSACMSGHDR{
			Len:   uintptr(alignedSizeofCmsghdr + sizeofSendMsgSize),
			Level: windows.IPPROTO_UDP,
			Type:  windows.UDP_SEND_MSG_SIZE,
		}
		_ = copy(msgBuf[alignedSizeofCmsghdr:], unsafe.Slice((*byte)(unsafe.Pointer(&m.SegmentSize)), sizeofSendMsgSize))
	}

	return b
}

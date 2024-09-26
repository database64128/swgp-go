package conn

import (
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/database64128/swgp-go/slicehelper"
	"golang.org/x/sys/windows"
)

const socketControlMessageBufferSize = sizeofCmsghdr + alignedSizeofInet6Pktinfo +
	sizeofCmsghdr + alignedSizeofCoalescedInfo

const (
	sizeofPtr           = int(unsafe.Sizeof(uintptr(0)))
	sizeofCmsghdr       = int(unsafe.Sizeof(Cmsghdr{}))
	sizeofInet4Pktinfo  = int(unsafe.Sizeof(Inet4Pktinfo{}))
	sizeofInet6Pktinfo  = int(unsafe.Sizeof(Inet6Pktinfo{}))
	sizeofCoalescedInfo = int(unsafe.Sizeof(uint32(0)))
)

// Structure CMSGHDR from ws2def.h
type Cmsghdr struct {
	Len   uintptr
	Level int32
	Type  int32
}

// Structure IN_PKTINFO from ws2ipdef.h
type Inet4Pktinfo struct {
	Addr    [4]byte
	Ifindex uint32
}

// Structure IN6_PKTINFO from ws2ipdef.h
type Inet6Pktinfo struct {
	Addr    [16]byte
	Ifindex uint32
}

func cmsgAlign(n int) int {
	return (n + sizeofPtr - 1) & ^(sizeofPtr - 1)
}

func parseSocketControlMessage(cmsg []byte) (m SocketControlMessage, err error) {
	for len(cmsg) >= sizeofCmsghdr {
		cmsghdr := (*Cmsghdr)(unsafe.Pointer(unsafe.SliceData(cmsg)))
		msgLen := int(cmsghdr.Len)
		msgSize := cmsgAlign(msgLen)
		if msgLen < sizeofCmsghdr || msgSize > len(cmsg) {
			return m, fmt.Errorf("invalid control message length %d", cmsghdr.Len)
		}

		switch {
		case cmsghdr.Level == windows.IPPROTO_IP && cmsghdr.Type == windows.IP_PKTINFO:
			if len(cmsg) < sizeofCmsghdr+sizeofInet4Pktinfo {
				return m, fmt.Errorf("invalid IP_PKTINFO control message length %d", cmsghdr.Len)
			}
			var pktinfo Inet4Pktinfo
			_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), sizeofInet4Pktinfo), cmsg[sizeofCmsghdr:])
			m.PktinfoAddr = netip.AddrFrom4(pktinfo.Addr)
			m.PktinfoIfindex = pktinfo.Ifindex

		case cmsghdr.Level == windows.IPPROTO_IPV6 && cmsghdr.Type == windows.IPV6_PKTINFO:
			if len(cmsg) < sizeofCmsghdr+sizeofInet6Pktinfo {
				return m, fmt.Errorf("invalid IPV6_PKTINFO control message length %d", cmsghdr.Len)
			}
			var pktinfo Inet6Pktinfo
			_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), sizeofInet6Pktinfo), cmsg[sizeofCmsghdr:])
			m.PktinfoAddr = netip.AddrFrom16(pktinfo.Addr)
			m.PktinfoIfindex = pktinfo.Ifindex

		case cmsghdr.Level == windows.IPPROTO_UDP && cmsghdr.Type == windows.UDP_COALESCED_INFO:
			if len(cmsg) < sizeofCmsghdr+sizeofCoalescedInfo {
				return m, fmt.Errorf("invalid UDP_COALESCED_INFO control message length %d", cmsghdr.Len)
			}
			_ = copy(unsafe.Slice((*byte)(unsafe.Pointer(&m.SegmentSize)), sizeofCoalescedInfo), cmsg[sizeofCmsghdr:])
		}

		cmsg = cmsg[msgSize:]
	}

	return m, nil
}

const (
	alignedSizeofInet4Pktinfo  = (sizeofInet4Pktinfo + sizeofPtr - 1) & ^(sizeofPtr - 1)
	alignedSizeofInet6Pktinfo  = (sizeofInet6Pktinfo + sizeofPtr - 1) & ^(sizeofPtr - 1)
	alignedSizeofCoalescedInfo = (sizeofCoalescedInfo + sizeofPtr - 1) & ^(sizeofPtr - 1)
)

func (m SocketControlMessage) appendTo(b []byte) []byte {
	switch {
	case m.PktinfoAddr.Is4():
		var msgBuf []byte
		b, msgBuf = slicehelper.Extend(b, sizeofCmsghdr+alignedSizeofInet4Pktinfo)
		cmsghdr := (*Cmsghdr)(unsafe.Pointer(unsafe.SliceData(msgBuf)))
		*cmsghdr = Cmsghdr{
			Len:   uintptr(sizeofCmsghdr + sizeofInet4Pktinfo),
			Level: windows.IPPROTO_IP,
			Type:  windows.IP_PKTINFO,
		}
		pktinfo := Inet4Pktinfo{
			Addr:    m.PktinfoAddr.As4(),
			Ifindex: m.PktinfoIfindex,
		}
		_ = copy(msgBuf[sizeofCmsghdr:], unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), sizeofInet4Pktinfo))

	case m.PktinfoAddr.Is6():
		var msgBuf []byte
		b, msgBuf = slicehelper.Extend(b, sizeofCmsghdr+alignedSizeofInet6Pktinfo)
		cmsghdr := (*Cmsghdr)(unsafe.Pointer(unsafe.SliceData(msgBuf)))
		*cmsghdr = Cmsghdr{
			Len:   uintptr(sizeofCmsghdr + sizeofInet6Pktinfo),
			Level: windows.IPPROTO_IPV6,
			Type:  windows.IPV6_PKTINFO,
		}
		pktinfo := Inet6Pktinfo{
			Addr:    m.PktinfoAddr.As16(),
			Ifindex: m.PktinfoIfindex,
		}
		_ = copy(msgBuf[sizeofCmsghdr:], unsafe.Slice((*byte)(unsafe.Pointer(&pktinfo)), sizeofInet6Pktinfo))
	}

	if m.SegmentSize > 0 {
		var msgBuf []byte
		b, msgBuf = slicehelper.Extend(b, sizeofCmsghdr+alignedSizeofCoalescedInfo)
		cmsghdr := (*Cmsghdr)(unsafe.Pointer(unsafe.SliceData(msgBuf)))
		*cmsghdr = Cmsghdr{
			Len:   uintptr(sizeofCmsghdr + sizeofCoalescedInfo),
			Level: windows.IPPROTO_UDP,
			Type:  windows.UDP_COALESCED_INFO,
		}
		_ = copy(msgBuf[sizeofCmsghdr:], unsafe.Slice((*byte)(unsafe.Pointer(&m.SegmentSize)), sizeofCoalescedInfo))
	}

	return b
}

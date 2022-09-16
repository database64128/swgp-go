package conn

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	IP_MTU_DISCOVER   = 71
	IPV6_MTU_DISCOVER = 71
)

// enum PMTUD_STATE from ws2ipdef.h
const (
	IP_PMTUDISC_NOT_SET = iota
	IP_PMTUDISC_DO
	IP_PMTUDISC_DONT
	IP_PMTUDISC_PROBE
	IP_PMTUDISC_MAX
)

// ListenUDP wraps Go's net.ListenConfig.ListenPacket and sets socket options on supported platforms.
//
// On Linux and Windows, IP_MTU_DISCOVER and IPV6_MTU_DISCOVER are set to IP_PMTUDISC_DO to disable IP fragmentation
// and encourage correct MTU settings. If pktinfo is true, IP_PKTINFO and IPV6_RECVPKTINFO are set to 1.
//
// On Linux, SO_MARK is set to user-specified value.
//
// On macOS and FreeBSD, IP_DONTFRAG, IPV6_DONTFRAG are set to 1 (Don't Fragment).
func ListenUDP(network string, laddr string, pktinfo bool, fwmark int) (conn *net.UDPConn, err error, serr error) {
	lc := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Set IP_MTU_DISCOVER for both v4 and v6.
				if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO); err != nil {
					serr = fmt.Errorf("failed to set socket option IP_MTU_DISCOVER: %w", err)
				}

				if network == "udp6" {
					if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, IPV6_MTU_DISCOVER, IP_PMTUDISC_DO); err != nil {
						serr = fmt.Errorf("failed to set socket option IPV6_MTU_DISCOVER: %w", err)
					}
				}

				if pktinfo {
					// Set IP_PKTINFO for both v4 and v6.
					if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_PKTINFO, 1); err != nil {
						serr = fmt.Errorf("failed to set socket option IP_PKTINFO: %w", err)
					}

					if network == "udp6" {
						if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_PKTINFO, 1); err != nil {
							serr = fmt.Errorf("failed to set socket option IPV6_PKTINFO: %w", err)
						}
					}
				}
			})
		},
	}

	pconn, err := lc.ListenPacket(context.Background(), network, laddr)
	if err != nil {
		return
	}
	conn = pconn.(*net.UDPConn)
	return
}

// Structure CMSGHDR from ws2def.h
type Cmsghdr struct {
	Len   uint
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

const (
	SizeofCmsghdr      = unsafe.Sizeof(Cmsghdr{})
	SizeofInet4Pktinfo = unsafe.Sizeof(Inet4Pktinfo{})
	SizeofInet6Pktinfo = unsafe.Sizeof(Inet6Pktinfo{})
)

const SizeofPtr = unsafe.Sizeof(uintptr(0))

// SocketControlMessageBufferSize specifies the buffer size for receiving socket control messages.
const SocketControlMessageBufferSize = SizeofCmsghdr + (SizeofInet6Pktinfo+SizeofPtr-1) & ^(SizeofPtr-1)

// ParsePktinfoCmsg parses a single socket control message of type IP_PKTINFO or IPV6_PKTINFO,
// and returns the IP address and index of the network interface the packet was received from,
// or an error.
//
// This function is only implemented for Linux and Windows. On other platforms, this is a no-op.
func ParsePktinfoCmsg(cmsg []byte) (netip.Addr, uint32, error) {
	if len(cmsg) < int(SizeofCmsghdr) {
		return netip.Addr{}, 0, fmt.Errorf("control message length %d is shorter than cmsghdr length", len(cmsg))
	}

	cmsghdr := (*Cmsghdr)(unsafe.Pointer(&cmsg[0]))

	switch {
	case cmsghdr.Level == windows.IPPROTO_IP && cmsghdr.Type == windows.IP_PKTINFO && len(cmsg) >= int(SizeofCmsghdr+SizeofInet4Pktinfo):
		pktinfo := (*Inet4Pktinfo)(unsafe.Pointer(&cmsg[SizeofCmsghdr]))
		return netip.AddrFrom4(pktinfo.Addr), pktinfo.Ifindex, nil

	case cmsghdr.Level == windows.IPPROTO_IPV6 && cmsghdr.Type == windows.IPV6_PKTINFO && len(cmsg) >= int(SizeofCmsghdr+SizeofInet6Pktinfo):
		pktinfo := (*Inet6Pktinfo)(unsafe.Pointer(&cmsg[SizeofCmsghdr]))
		return netip.AddrFrom16(pktinfo.Addr), pktinfo.Ifindex, nil

	default:
		return netip.Addr{}, 0, fmt.Errorf("unknown control message level %d type %d", cmsghdr.Level, cmsghdr.Type)
	}
}

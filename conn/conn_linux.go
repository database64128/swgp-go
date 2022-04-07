package conn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// UDPOOBBufferSize specifies the size of buffer to allocate for receiving OOB data
// when calling the ReadMsgUDP method on a *net.UDPConn returned by this package's ListenUDP function.
const UDPOOBBufferSize = unix.SizeofCmsghdr + unix.SizeofInet6Pktinfo

var ErrEmptyOob = errors.New("length of oob is 0")

// ListenUDP wraps Go's net.ListenConfig.ListenPacket and sets socket options on supported platforms.
//
// On Linux, IP_PKTINFO and IPV6_RECVPKTINFO are set to 1;
// IP_MTU_DISCOVER, IPV6_MTU_DISCOVER are set to IP_PMTUDISC_DO to disable IP fragmentation to encourage correct MTU settings.
// SO_MARK is set to user-specified value.
//
// On Windows, IP_MTU_DISCOVER, IPV6_MTU_DISCOVER are set to IP_PMTUDISC_DO.
//
// On macOS and FreeBSD, IP_DONTFRAG, IPV6_DONTFRAG are set to 1 (Don't Fragment).
func ListenUDP(network string, laddr string, fwmark int) (conn *net.UDPConn, err error, serr error) {
	lc := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Set IP_PKTINFO, IP_MTU_DISCOVER for both v4 and v6.
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1); err != nil {
					serr = fmt.Errorf("failed to set socket option IP_PKTINFO: %w", err)
				}

				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
					serr = fmt.Errorf("failed to set socket option IP_MTU_DISCOVER: %w", err)
				}

				if network == "udp6" {
					if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1); err != nil {
						serr = fmt.Errorf("failed to set socket option IPV6_RECVPKTINFO: %w", err)
					}

					if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
						serr = fmt.Errorf("failed to set socket option IPV6_MTU_DISCOVER: %w", err)
					}
				}

				if fwmark != 0 {
					if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, fwmark); err != nil {
						serr = fmt.Errorf("failed to set socket option SO_MARK: %w", err)
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

// GetOobForCache filters out irrelevant OOB messages
// and returns only IP_PKTINFO or IPV6_PKTINFO socket control messages.
//
// Errors returned by this function can be safely ignored,
// or printed as debug logs.
func GetOobForCache(clientOob []byte) ([]byte, error) {
	switch len(clientOob) {
	case unix.SizeofCmsghdr + unix.SizeofInet4Pktinfo:
		return getOobForCache4(clientOob), nil
	case unix.SizeofCmsghdr + unix.SizeofInet6Pktinfo:
		return getOobForCache6(clientOob), nil
	case 0:
		return nil, ErrEmptyOob
	default:
		return nil, fmt.Errorf("unknown oob length: %d", len(clientOob))
	}
}

type oob4 struct {
	cmsghdr unix.Cmsghdr
	pktinfo unix.Inet4Pktinfo
}

func getOobForCache4(clientOob4 []byte) []byte {
	cmsg := (*oob4)(unsafe.Pointer(&clientOob4))
	if cmsg.cmsghdr.Level == unix.IPPROTO_IP && cmsg.cmsghdr.Type == unix.IP_PKTINFO {
		return (*[unix.SizeofCmsghdr + unix.SizeofInet4Pktinfo]byte)(unsafe.Pointer(&oob4{
			cmsghdr: unix.Cmsghdr{
				Level: unix.IPPROTO_IP,
				Type:  unix.IP_PKTINFO,
				Len:   unix.SizeofCmsghdr + unix.SizeofInet4Pktinfo,
			},
			pktinfo: unix.Inet4Pktinfo{
				Ifindex:  cmsg.pktinfo.Ifindex,
				Spec_dst: cmsg.pktinfo.Spec_dst,
			},
		}))[:]
	}
	return nil
}

type oob6 struct {
	cmsghdr unix.Cmsghdr
	pktinfo unix.Inet6Pktinfo
}

func getOobForCache6(clientOob6 []byte) []byte {
	cmsg := (*oob6)(unsafe.Pointer(&clientOob6))
	if cmsg.cmsghdr.Level == unix.IPPROTO_IPV6 && cmsg.cmsghdr.Type == unix.IPV6_PKTINFO {
		return (*[unix.SizeofCmsghdr + unix.SizeofInet6Pktinfo]byte)(unsafe.Pointer(&oob6{
			cmsghdr: unix.Cmsghdr{
				Level: unix.IPPROTO_IPV6,
				Type:  unix.IPV6_PKTINFO,
				Len:   unix.SizeofCmsghdr + unix.SizeofInet6Pktinfo,
			},
			pktinfo: unix.Inet6Pktinfo{
				Addr:    cmsg.pktinfo.Addr,
				Ifindex: cmsg.pktinfo.Ifindex,
			},
		}))[:]
	}
	return nil
}

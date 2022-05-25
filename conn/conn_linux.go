package conn

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
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
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
					serr = fmt.Errorf("failed to set socket option IP_MTU_DISCOVER: %w", err)
				}

				if network == "udp6" {
					if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
						serr = fmt.Errorf("failed to set socket option IPV6_MTU_DISCOVER: %w", err)
					}
				}

				if pktinfo {
					// Set IP_PKTINFO for both v4 and v6.
					if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1); err != nil {
						serr = fmt.Errorf("failed to set socket option IP_PKTINFO: %w", err)
					}

					if network == "udp6" {
						if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1); err != nil {
							serr = fmt.Errorf("failed to set socket option IPV6_RECVPKTINFO: %w", err)
						}
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

// On Linux and Windows, UpdateOobCache filters out irrelevant OOB messages,
// saves IP_PKTINFO or IPV6_PKTINFO socket control messages to the OOB cache,
// and returns the updated OOB cache slice.
//
// The returned OOB cache is unchanged if no relevant control messages
// are found.
//
// On other platforms, this is a no-op.
func UpdateOobCache(oobCache, oob []byte, logger *zap.Logger) ([]byte, error) {
	// Since we only set IP_PKTINFO and/or IPV6_PKTINFO,
	// Inet4Pktinfo or Inet6Pktinfo should be the first
	// and only socket control message returned.
	// Therefore we simplify the process by not looping
	// through the OOB data.
	oobLen := len(oob)
	switch {
	case oobLen == 0:
		return oobCache, nil
	case oobLen < unix.SizeofCmsghdr:
		return oobCache, fmt.Errorf("oob length %d shorter than cmsghdr length", oobLen)
	}

	cmsghdr := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))

	switch {
	case cmsghdr.Level == unix.IPPROTO_IP && cmsghdr.Type == unix.IP_PKTINFO && oobLen >= unix.SizeofCmsghdr+unix.SizeofInet4Pktinfo:
		pktinfo := (*unix.Inet4Pktinfo)(unsafe.Pointer(&oob[unix.SizeofCmsghdr]))
		// Clear destination address.
		pktinfo.Addr = [4]byte{}
		// logger.Debug("Matched Inet4Pktinfo", zap.Int32("ifindex", pktinfo.Ifindex))

	case cmsghdr.Level == unix.IPPROTO_IPV6 && cmsghdr.Type == unix.IPV6_PKTINFO && oobLen >= unix.SizeofCmsghdr+unix.SizeofInet6Pktinfo:
		// pktinfo := (*unix.Inet6Pktinfo)(unsafe.Pointer(&oob[unix.SizeofCmsghdr]))
		// logger.Debug("Matched Inet6Pktinfo", zap.Uint32("ifindex", pktinfo.Ifindex))

	default:
		return oobCache, fmt.Errorf("unknown control message level %d type %d", cmsghdr.Level, cmsghdr.Type)
	}

	return append(oobCache[:0], oob...), nil
}

// Source: include/uapi/linux/uio.h
const UIO_MAXIOV = 1024

type Mmsghdr struct {
	Msghdr unix.Msghdr
	Msglen uint32
}

func AddrPortToSockaddr(addrPort netip.AddrPort) (name *byte, namelen uint32) {
	if addrPort.Addr().Is4() {
		rsa4 := AddrPortToSockaddrInet4(addrPort)
		name = (*byte)(unsafe.Pointer(&rsa4))
		namelen = unix.SizeofSockaddrInet4
	} else {
		rsa6 := AddrPortToSockaddrInet6(addrPort)
		name = (*byte)(unsafe.Pointer(&rsa6))
		namelen = unix.SizeofSockaddrInet6
	}

	return
}

func AddrPortToSockaddrInet4(addrPort netip.AddrPort) unix.RawSockaddrInet4 {
	addr := addrPort.Addr()
	port := addrPort.Port()
	rsa4 := unix.RawSockaddrInet4{
		Family: unix.AF_INET,
		Addr:   addr.As4(),
	}
	p := (*[2]byte)(unsafe.Pointer(&rsa4.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	return rsa4
}

func AddrPortToSockaddrInet6(addrPort netip.AddrPort) unix.RawSockaddrInet6 {
	addr := addrPort.Addr()
	port := addrPort.Port()
	rsa6 := unix.RawSockaddrInet6{
		Family: unix.AF_INET6,
		Addr:   addr.As16(),
	}
	p := (*[2]byte)(unsafe.Pointer(&rsa6.Port))
	p[0] = byte(port >> 8)
	p[1] = byte(port)
	return rsa6
}

func Recvmmsg(conn *net.UDPConn, msgvec []Mmsghdr) (n int, err error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("failed to get syscall.RawConn: %w", err)
	}

	perr := rawConn.Read(func(fd uintptr) (done bool) {
		r0, _, e1 := unix.Syscall6(unix.SYS_RECVMMSG, fd, uintptr(unsafe.Pointer(&msgvec[0])), uintptr(len(msgvec)), 0, 0, 0)
		if e1 == unix.EAGAIN || e1 == unix.EWOULDBLOCK {
			return false
		}
		if e1 != 0 {
			err = fmt.Errorf("recvmmsg failed: %w", e1)
			return true
		}
		n = int(r0)
		return true
	})

	if err == nil {
		err = perr
	}

	return
}

func Sendmmsg(conn *net.UDPConn, msgvec []Mmsghdr) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get syscall.RawConn: %w", err)
	}

	var processed int

	perr := rawConn.Write(func(fd uintptr) (done bool) {
		r0, _, e1 := unix.Syscall6(unix.SYS_SENDMMSG, fd, uintptr(unsafe.Pointer(&msgvec[processed])), uintptr(len(msgvec)-processed), 0, 0, 0)
		if e1 == unix.EAGAIN || e1 == unix.EWOULDBLOCK {
			return false
		}
		if e1 != 0 {
			err = fmt.Errorf("sendmmsg failed: %w", e1)
			return true
		}
		processed += int(r0)
		return processed >= len(msgvec)
	})

	if err == nil {
		err = perr
	}

	return err
}

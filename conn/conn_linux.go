package conn

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func setFwmark(fd, fwmark int) error {
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, fwmark); err != nil {
		return fmt.Errorf("failed to set socket option SO_MARK: %w", err)
	}
	return nil
}

func setTrafficClass(fd int, network string, trafficClass int) error {
	// Set IP_TOS for both v4 and v6.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TOS, trafficClass); err != nil {
		return fmt.Errorf("failed to set socket option IP_TOS: %w", err)
	}

	switch network {
	case "tcp4", "udp4":
	case "tcp6", "udp6":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TCLASS, trafficClass); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_TCLASS: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}

	return nil
}

func setPMTUD(fd int, network string) error {
	// Set IP_MTU_DISCOVER for both v4 and v6.
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
		return fmt.Errorf("failed to set socket option IP_MTU_DISCOVER: %w", err)
	}

	switch network {
	case "tcp4", "udp4":
	case "tcp6", "udp6":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IP_PMTUDISC_DO); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_MTU_DISCOVER: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}

	return nil
}

func setRecvPktinfo(fd int, network string) error {
	switch network {
	case "udp4":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_PKTINFO, 1); err != nil {
			return fmt.Errorf("failed to set socket option IP_PKTINFO: %w", err)
		}
	case "udp6":
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1); err != nil {
			return fmt.Errorf("failed to set socket option IPV6_RECVPKTINFO: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network: %s", network)
	}
	return nil
}

func (lso ListenerSocketOptions) buildSetFns() setFuncSlice {
	return setFuncSlice{}.
		appendSetFwmarkFunc(lso.Fwmark).
		appendSetTrafficClassFunc(lso.TrafficClass).
		appendSetPMTUDFunc(lso.PathMTUDiscovery).
		appendSetRecvPktinfoFunc(lso.ReceivePacketInfo)
}

// ListenUDP wraps [net.ListenConfig.ListenPacket] and sets socket options on supported platforms.
//
// On Linux and Windows, IP_MTU_DISCOVER and IPV6_MTU_DISCOVER are set to IP_PMTUDISC_DO to disable IP fragmentation
// and encourage correct MTU settings. If pktinfo is true, IP_PKTINFO and IPV6_RECVPKTINFO are set to 1.
//
// On Linux, SO_MARK is set to user-specified value.
//
// On macOS and FreeBSD, IP_DONTFRAG, IPV6_DONTFRAG are set to 1 (Don't Fragment).
func ListenUDP(network string, laddr string, pktinfo bool, fwmark int) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) (err error) {
			if cerr := c.Control(func(fd uintptr) {
				if err = setPMTUD(int(fd), network); err != nil {
					return
				}

				if pktinfo {
					if err = setRecvPktinfo(int(fd), network); err != nil {
						return
					}
				}

				if fwmark != 0 {
					err = setFwmark(int(fd), fwmark)
				}
			}); cerr != nil {
				return cerr
			}
			return
		},
	}

	pc, err := lc.ListenPacket(context.Background(), network, laddr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
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

func SockaddrToAddrPort(name *byte, namelen uint32) (netip.AddrPort, error) {
	switch namelen {
	case unix.SizeofSockaddrInet4:
		rsa4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(name))
		portp := (*[2]byte)(unsafe.Pointer(&rsa4.Port))
		port := uint16(portp[0])<<8 + uint16(portp[1])
		ip := netip.AddrFrom4(rsa4.Addr)
		return netip.AddrPortFrom(ip, port), nil

	case unix.SizeofSockaddrInet6:
		rsa6 := (*unix.RawSockaddrInet6)(unsafe.Pointer(name))
		portp := (*[2]byte)(unsafe.Pointer(&rsa6.Port))
		port := uint16(portp[0])<<8 + uint16(portp[1])
		ip := netip.AddrFrom16(rsa6.Addr)
		return netip.AddrPortFrom(ip, port), nil

	default:
		return netip.AddrPort{}, fmt.Errorf("bad sockaddr length: %d", namelen)
	}
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

func Sendmmsg(conn *net.UDPConn, msgvec []Mmsghdr) (n int, err error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("failed to get syscall.RawConn: %w", err)
	}

	perr := rawConn.Write(func(fd uintptr) (done bool) {
		r0, _, e1 := unix.Syscall6(unix.SYS_SENDMMSG, fd, uintptr(unsafe.Pointer(&msgvec[0])), uintptr(len(msgvec)), 0, 0, 0)
		if e1 == unix.EAGAIN || e1 == unix.EWOULDBLOCK {
			return false
		}
		if e1 != 0 {
			err = fmt.Errorf("sendmmsg failed: %w", e1)
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

// WriteMsgvec repeatedly calls sendmmsg(2) until all messages in msgvec are written to the socket.
//
// If the syscall returns an error, this function drops the message that caused the error,
// and continues sending. Only the last encountered error is returned.
func WriteMsgvec(conn *net.UDPConn, msgvec []Mmsghdr) error {
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
			r0 = 1
		}
		processed += int(r0)
		return processed >= len(msgvec)
	})

	if err == nil {
		err = perr
	}

	return err
}

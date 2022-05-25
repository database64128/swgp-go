//go:build darwin || freebsd

package conn

import (
	"context"
	"fmt"
	"net"
	"syscall"

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
				switch network {
				case "udp4":
					if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1); err != nil {
						serr = fmt.Errorf("failed to set socket option IP_DONTFRAG: %w", err)
					}
				case "udp6":
					if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1); err != nil {
						serr = fmt.Errorf("failed to set socket option IPV6_DONTFRAG: %w", err)
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

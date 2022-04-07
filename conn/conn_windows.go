package conn

import (
	"context"
	"fmt"
	"net"
	"syscall"

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
				// Set IP_MTU_DISCOVER for both v4 and v6.
				if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO); err != nil {
					serr = fmt.Errorf("failed to set socket option IP_MTU_DISCOVER: %w", err)
				}

				if network == "udp6" {
					if err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, IPV6_MTU_DISCOVER, IP_PMTUDISC_DO); err != nil {
						serr = fmt.Errorf("failed to set socket option IPV6_MTU_DISCOVER: %w", err)
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

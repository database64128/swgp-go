package conn

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// UDPOOBBufferSize specifies the size of buffer to allocate for receiving OOB data
// when calling the ReadMsgUDP method on a *net.UDPConn returned by this package's ListenUDP function.
const UDPOOBBufferSize = 128

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
func GetOobForCache(oob []byte, logger *zap.Logger) ([]byte, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}

	for _, msg := range msgs {
		switch {
		case msg.Header.Level == unix.IPPROTO_IP && msg.Header.Type == unix.IP_PKTINFO && len(msg.Data) >= unix.SizeofInet4Pktinfo:
			pktinfo := (*unix.Inet4Pktinfo)(unsafe.Pointer(&msg.Data[0]))
			return unix.PktInfo4(&unix.Inet4Pktinfo{
				Ifindex:  pktinfo.Ifindex,
				Spec_dst: pktinfo.Spec_dst,
			}), nil

		case msg.Header.Level == unix.IPPROTO_IPV6 && msg.Header.Type == unix.IPV6_PKTINFO && len(msg.Data) >= unix.SizeofInet6Pktinfo:
			pktinfo := (*unix.Inet6Pktinfo)(unsafe.Pointer(&msg.Data[0]))
			return unix.PktInfo6(pktinfo), nil

		default:
			logger.Debug("Skipping unknown oob control message",
				zap.Uint64("cmsghdrLen", msg.Header.Len),
				zap.Int32("cmsghdrLevel", msg.Header.Level),
				zap.Int32("cmsghdrType", msg.Header.Type),
			)
		}
	}

	return nil, fmt.Errorf("PKTINFO not found in %d control messages", len(msgs))
}

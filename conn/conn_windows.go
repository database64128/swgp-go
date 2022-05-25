package conn

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"go.uber.org/zap"
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

// Defined for getting structure size using unsafe.Sizeof.
var (
	cmsghdrForSize      Cmsghdr
	inet4PktinfoForSize Inet4Pktinfo
	inet6PktinfoForSize Inet6Pktinfo
)

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
	case oobLen < int(unsafe.Sizeof(cmsghdrForSize)):
		return oobCache, fmt.Errorf("oob length %d shorter than cmsghdr length", oobLen)
	}

	cmsghdr := (*Cmsghdr)(unsafe.Pointer(&oob[0]))

	switch {
	case cmsghdr.Level == windows.IPPROTO_IP && cmsghdr.Type == windows.IP_PKTINFO && oobLen >= int(unsafe.Sizeof(cmsghdrForSize)+unsafe.Sizeof(inet4PktinfoForSize)):
		// pktinfo := (*Inet4Pktinfo)(unsafe.Pointer(&oob[unsafe.Sizeof(cmsghdrForSize)]))
		// logger.Debug("Matched Inet4Pktinfo", zap.Uint32("ifindex", pktinfo.Ifindex))
	case cmsghdr.Level == windows.IPPROTO_IPV6 && cmsghdr.Type == windows.IPV6_PKTINFO && oobLen >= int(unsafe.Sizeof(cmsghdrForSize)+unsafe.Sizeof(inet6PktinfoForSize)):
		// pktinfo := (*Inet6Pktinfo)(unsafe.Pointer(&oob[unsafe.Sizeof(cmsghdrForSize)]))
		// logger.Debug("Matched Inet6Pktinfo", zap.Uint32("ifindex", pktinfo.Ifindex))
	default:
		return oobCache, fmt.Errorf("unknown control message level %d type %d", cmsghdr.Level, cmsghdr.Type)
	}

	return append(oobCache[:0], oob...), nil
}

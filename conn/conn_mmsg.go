//go:build linux || netbsd

package conn

import (
	"context"
	"net"
)

// ListenUDPMmsgConn is like [ListenUDP] but wraps the [*net.UDPConn] in a [MmsgConn] for
// reading and writing multiple messages using the recvmmsg(2) and sendmmsg(2) system calls.
func (lc *ListenConfig) ListenUDPMmsgConn(ctx context.Context, network, address string) (c MmsgConn, info SocketInfo, err error) {
	info.MaxUDPGSOSegments = 1
	nlc := net.ListenConfig{
		Control: lc.fns.controlFunc(&info),
	}
	pc, err := nlc.ListenPacket(ctx, network, address)
	if err != nil {
		return MmsgConn{}, info, err
	}
	c, err = NewMmsgConn(pc.(*net.UDPConn))
	return c, info, err
}

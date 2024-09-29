//go:build linux || netbsd

package conn

import (
	"context"
	"net"
)

// ListenUDPRawConn is like [ListenUDP] but wraps the [*net.UDPConn] in a [rawUDPConn] for batch I/O.
func (lc *ListenConfig) ListenUDPRawConn(ctx context.Context, network, address string) (c rawUDPConn, info SocketInfo, err error) {
	nlc := net.ListenConfig{
		Control: lc.fns.controlFunc(&info),
	}
	pc, err := nlc.ListenPacket(ctx, network, address)
	if err != nil {
		return rawUDPConn{}, info, err
	}
	c, err = NewRawUDPConn(pc.(*net.UDPConn))
	return c, info, err
}

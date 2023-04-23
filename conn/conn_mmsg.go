//go:build linux || netbsd

package conn

import (
	"context"
	"net"
)

// ListenUDPRawConn is like [ListenUDP] but wraps the [*net.UDPConn] in a [rawUDPConn] for batch I/O.
func (lc *ListenConfig) ListenUDPRawConn(ctx context.Context, network, address string) (rawUDPConn, error) {
	pc, err := (*net.ListenConfig)(lc).ListenPacket(ctx, network, address)
	if err != nil {
		return rawUDPConn{}, err
	}
	return NewRawUDPConn(pc.(*net.UDPConn))
}

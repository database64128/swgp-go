//go:build linux || netbsd

package conn

import (
	"context"
)

// ListenMmsgConn is like [Listen] but wraps the [*net.UDPConn] in a [MmsgConn] for
// batch receiving and sending using the recvmmsg(2) and sendmmsg(2) system calls.
func (cfg *UDPSocketConfig) ListenMmsgConn(ctx context.Context, network, address string) (c MmsgConn, info SocketInfo, err error) {
	uc, info, err := cfg.Listen(ctx, network, address)
	if err != nil {
		return MmsgConn{}, info, err
	}
	c, err = NewMmsgConn(uc)
	return c, info, err
}

// DialMmsgConn is like [Dial] but wraps the [*net.UDPConn] in a [MmsgConn] for
// batch receiving and sending using the recvmmsg(2) and sendmmsg(2) system calls.
func (cfg *UDPSocketConfig) DialMmsgConn(ctx context.Context, localAddr Addr, network, address string) (c MmsgConn, info SocketInfo, err error) {
	uc, info, err := cfg.Dial(ctx, localAddr, network, address)
	if err != nil {
		return MmsgConn{}, info, err
	}
	c, err = NewMmsgConn(uc)
	return c, info, err
}

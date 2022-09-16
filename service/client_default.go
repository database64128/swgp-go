//go:build !linux

package service

func (c *client) setRelayFunc() {
	c.recvFromWgConn = c.recvFromWgConnGeneric
}

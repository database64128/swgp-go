//go:build !linux

package service

func (c *client) setRelayFunc(batchMode string) {
	c.recvFromWgConn = c.recvFromWgConnGeneric
}

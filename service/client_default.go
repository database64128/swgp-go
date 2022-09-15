//go:build !linux

package service

func (c *client) setRecvAndRelayFunctions() {
	c.recvFromWgConn = c.recvFromWgConnGeneric
	c.relayWgToProxy = c.relayWgToProxyGeneric
	c.relayProxyToWg = c.relayProxyToWgGeneric
}

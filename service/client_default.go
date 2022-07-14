//go:build !linux

package service

func (c *client) setRelayWgToProxyFunc() {
	c.relayWgToProxy = c.relayWgToProxyGeneric
}

func (c *client) setRelayProxyToWgFunc() {
	c.relayProxyToWg = c.relayProxyToWgGeneric
}

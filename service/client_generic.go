//go:build !linux && !netbsd

package service

func (c *client) setStartFunc(_ string) {
	c.startFunc = c.startGeneric
}

//go:build !linux && !netbsd

package service

func (c *client) setStartFunc(batchMode string) {
	c.startFunc = c.startGeneric
}

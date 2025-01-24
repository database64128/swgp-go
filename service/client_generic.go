//go:build !linux && !netbsd

package service

import "context"

func (c *client) start(ctx context.Context) error {
	return c.startGeneric(ctx)
}

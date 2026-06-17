//go:build !linux && !netbsd

package service

import "context"

func (c *Client) start(ctx context.Context) error {
	return c.startGeneric(ctx)
}

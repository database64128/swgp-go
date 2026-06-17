//go:build !linux && !netbsd

package service

import "context"

func (s *Server) start(ctx context.Context) error {
	return s.startGeneric(ctx)
}

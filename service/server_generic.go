//go:build !linux && !netbsd

package service

func (s *server) setStartFunc(_ string) {
	s.startFunc = s.startGeneric
}

//go:build !linux && !netbsd

package service

func (s *server) setStartFunc(batchMode string) {
	s.startFunc = s.startGeneric
}

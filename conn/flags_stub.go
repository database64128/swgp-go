//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !zos

package conn

func parseFlagsForError(_ int) error {
	return nil
}

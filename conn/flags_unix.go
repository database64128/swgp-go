//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || zos

package conn

import "golang.org/x/sys/unix"

func parseFlagsForError(flags int) error {
	if flags&unix.MSG_TRUNC != 0 {
		return ErrMessageTruncated
	}

	if flags&unix.MSG_CTRUNC != 0 {
		return ErrControlMessageTruncated
	}

	return nil
}

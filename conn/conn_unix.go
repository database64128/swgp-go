//go:build linux || darwin || freebsd

package conn

import (
	"errors"

	"golang.org/x/sys/unix"
)

var (
	ErrMessageTruncated        = errors.New("the packet is larger than the supplied buffer")
	ErrControlMessageTruncated = errors.New("the control message is larger than the supplied buffer")
)

// ParseFlagsForError parses the message flags returned by
// the ReadMsgUDPAddrPort method and returns an error if MSG_TRUNC
// is set, indicating that the returned packet was truncated.
//
// The check is skipped on Windows, because an error (WSAEMSGSIZE)
// is also returned when MSG_PARTIAL is set.
func ParseFlagsForError(flags int) error {
	if flags&unix.MSG_TRUNC == unix.MSG_TRUNC {
		return ErrMessageTruncated
	}

	if flags&unix.MSG_CTRUNC == unix.MSG_CTRUNC {
		return ErrControlMessageTruncated
	}

	return nil
}

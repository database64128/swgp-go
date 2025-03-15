package conn

import "errors"

var (
	ErrMessageTruncated        = errors.New("the packet is larger than the supplied buffer")
	ErrControlMessageTruncated = errors.New("the control message is larger than the supplied buffer")
)

// ParseFlagsForError parses the message flags set by recvmsg(2) and friends, and returns an error
// if the flags indicate that the message itself or the socket control message was truncated.
//
// The check is skipped on Windows, because WSAEMSGSIZE is returned when MSG_PARTIAL is set.
func ParseFlagsForError(flags int) error {
	return parseFlagsForError(flags)
}

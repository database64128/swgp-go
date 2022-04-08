//go:build !linux && !darwin && !freebsd

package conn

// ParseFlagsForError parses the message flags returned by
// the ReadMsgUDPAddrPort method and returns an error if MSG_TRUNC
// is set, indicating that the returned packet was truncated.
//
// The check is skipped on Windows, because an error (WSAEMSGSIZE)
// is also returned when MSG_PARTIAL is set.
func ParseFlagsForError(flags int) error {
	return nil
}

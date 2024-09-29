//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || zos

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
	if flags&unix.MSG_TRUNC != 0 {
		return ErrMessageTruncated
	}

	if flags&unix.MSG_CTRUNC != 0 {
		return ErrControlMessageTruncated
	}

	return nil
}

func (fns setFuncSlice) appendSetTrafficClassFunc(trafficClass int) setFuncSlice {
	if trafficClass != 0 {
		return append(fns, func(fd int, network string, _ *SocketInfo) error {
			return setTrafficClass(fd, network, trafficClass)
		})
	}
	return fns
}

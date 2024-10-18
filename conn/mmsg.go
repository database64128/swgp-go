//go:build linux || netbsd

package conn

import (
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// MmsgConn wraps a [*net.UDPConn] and provides methods for reading and writing
// multiple messages using the recvmmsg(2) and sendmmsg(2) system calls.
type MmsgConn struct {
	*net.UDPConn
	rawConn syscall.RawConn
}

// NewMmsgConn returns a new [MmsgConn] for udpConn.
func NewMmsgConn(udpConn *net.UDPConn) (MmsgConn, error) {
	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		return MmsgConn{}, err
	}

	return MmsgConn{
		UDPConn: udpConn,
		rawConn: rawConn,
	}, nil
}

// MmsgRConn provides read access to the [MmsgConn].
//
// MmsgRConn is not safe for concurrent use.
// Always create a new MmsgRConn for each goroutine.
type MmsgRConn struct {
	MmsgConn
	rawReadFunc func(fd uintptr) (done bool)
	readMsgvec  []Mmsghdr
	readFlags   int
	readN       int
	readErr     error
}

// MmsgWConn provides write access to the [MmsgConn].
//
// MmsgWConn is not safe for concurrent use.
// Always create a new MmsgWConn for each goroutine.
type MmsgWConn struct {
	MmsgConn
	rawWriteFunc func(fd uintptr) (done bool)
	writeMsgvec  []Mmsghdr
	writeFlags   int
	writeN       int
	writeErr     error
}

// NewRConn returns the connection wrapped in a new [*MmsgRConn] for batch reading.
func (c MmsgConn) NewRConn() *MmsgRConn {
	rc := MmsgRConn{
		MmsgConn: c,
	}

	rc.rawReadFunc = func(fd uintptr) (done bool) {
		var errno syscall.Errno
		rc.readN, errno = recvmmsg(int(fd), rc.readMsgvec, rc.readFlags)
		switch errno {
		case 0:
			rc.readErr = nil
		case syscall.EAGAIN:
			return false
		default:
			rc.readErr = os.NewSyscallError("recvmmsg", errno)
		}
		return true
	}

	return &rc
}

// NewWConn returns the connection wrapped in a new [*MmsgWConn] for batch writing.
func (c MmsgConn) NewWConn() *MmsgWConn {
	wc := MmsgWConn{
		MmsgConn: c,
	}

	wc.rawWriteFunc = func(fd uintptr) (done bool) {
		wc.writeN = 0
		for {
			n, errno := sendmmsg(int(fd), wc.writeMsgvec, wc.writeFlags)
			switch errno {
			case 0:
			case syscall.EAGAIN:
				return false
			default:
				wc.writeErr = os.NewSyscallError("sendmmsg", errno)
				return true
			}

			wc.writeMsgvec = wc.writeMsgvec[n:]
			wc.writeN += n

			if len(wc.writeMsgvec) == 0 {
				wc.writeErr = nil
				return true
			}

			// sendmmsg(2) may return less than vlen in one of the following cases:
			//
			//   - The socket write buffer is full.
			//   - vlen is greater than UIO_MAXIOV (1024).
			//   - Sending the next message would return an error.
			//
			// The first case is the only one where it's safe to clear write readiness.
			// The other cases require the caller to retry sending the remaining messages.
			// Unfortunately, the API does not tell us which one is the case, so we always
			// retry the call with the remaining messages.
		}
	}

	return &wc
}

// ReadMsgs reads as many messages as possible into msgvec
// and returns the number of messages read or an error.
func (c *MmsgRConn) ReadMsgs(msgvec []Mmsghdr, flags int) (int, error) {
	c.readMsgvec = msgvec
	c.readFlags = flags
	if err := c.rawConn.Read(c.rawReadFunc); err != nil {
		return 0, err
	}
	return c.readN, c.readErr
}

// WriteMsgs writes the messages in msgvec to the connection.
// It returns the number of messages written as n, and if n < len(msgvec),
// the error from writing the n-th message.
func (c *MmsgWConn) WriteMsgs(msgvec []Mmsghdr, flags int) (int, error) {
	c.writeMsgvec = msgvec
	c.writeFlags = flags
	if err := c.rawConn.Write(c.rawWriteFunc); err != nil {
		return 0, err
	}
	return c.writeN, c.writeErr
}

type Mmsghdr struct {
	Msghdr unix.Msghdr
	Msglen uint32
}

func mmsgSyscall(trap uintptr, fd int, msgvec []Mmsghdr, flags int) (int, syscall.Errno) {
	r0, _, e1 := unix.Syscall6(trap, uintptr(fd), uintptr(unsafe.Pointer(unsafe.SliceData(msgvec))), uintptr(len(msgvec)), uintptr(flags), 0, 0)
	if e1 != 0 {
		return 0, e1
	}
	return int(r0), 0
}

func recvmmsg(fd int, msgvec []Mmsghdr, flags int) (int, syscall.Errno) {
	return mmsgSyscall(SYS_RECVMMSG, fd, msgvec, flags)
}

func sendmmsg(fd int, msgvec []Mmsghdr, flags int) (int, syscall.Errno) {
	return mmsgSyscall(unix.SYS_SENDMMSG, fd, msgvec, flags)
}

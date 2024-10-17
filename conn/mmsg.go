//go:build linux || netbsd

package conn

import (
	"net"
	"os"
	"syscall"
)

type rawUDPConn struct {
	*net.UDPConn
	rawConn syscall.RawConn
}

// NewRawUDPConn wraps a [net.UDPConn] in a [rawUDPConn] for batch I/O.
func NewRawUDPConn(udpConn *net.UDPConn) (rawUDPConn, error) {
	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		return rawUDPConn{}, err
	}

	return rawUDPConn{
		UDPConn: udpConn,
		rawConn: rawConn,
	}, nil
}

// MmsgRConn wraps a [net.UDPConn] and provides the [ReadMsgs] method
// for reading multiple messages in a single recvmmsg(2) system call.
//
// [MmsgRConn] is not safe for concurrent use.
// Use the [RConn] method to create a new [MmsgRConn] instance for each goroutine.
type MmsgRConn struct {
	rawUDPConn
	rawReadFunc func(fd uintptr) (done bool)
	readMsgvec  []Mmsghdr
	readFlags   int
	readN       int
	readErr     error
}

// MmsgWConn wraps a [net.UDPConn] and provides the [WriteMsgs] method
// for writing multiple messages in a single sendmmsg(2) system call.
//
// [MmsgWConn] is not safe for concurrent use.
// Use the [WConn] method to create a new [MmsgWConn] instance for each goroutine.
type MmsgWConn struct {
	rawUDPConn
	rawWriteFunc func(fd uintptr) (done bool)
	writeMsgvec  []Mmsghdr
	writeFlags   int
	writeErrno   syscall.Errno
}

// RConn returns a new [MmsgRConn] instance for batch reading.
func (c rawUDPConn) RConn() *MmsgRConn {
	mmsgRConn := MmsgRConn{
		rawUDPConn: c,
	}

	mmsgRConn.rawReadFunc = func(fd uintptr) (done bool) {
		var errno syscall.Errno
		mmsgRConn.readN, errno = recvmmsg(int(fd), mmsgRConn.readMsgvec, mmsgRConn.readFlags)
		switch errno {
		case 0:
		case syscall.EAGAIN:
			return false
		default:
			mmsgRConn.readErr = os.NewSyscallError("recvmmsg", errno)
		}
		return true
	}

	return &mmsgRConn
}

// WConn returns a new [MmsgWConn] instance for batch writing.
func (c rawUDPConn) WConn() *MmsgWConn {
	mmsgWConn := MmsgWConn{
		rawUDPConn: c,
	}

	mmsgWConn.rawWriteFunc = func(fd uintptr) (done bool) {
		for {
			n, errno := sendmmsg(int(fd), mmsgWConn.writeMsgvec, mmsgWConn.writeFlags)
			switch errno {
			case 0:
			case syscall.EAGAIN:
				return false
			default:
				mmsgWConn.writeErrno = errno
				mmsgWConn.writeMsgvec = mmsgWConn.writeMsgvec[1:]
				if len(mmsgWConn.writeMsgvec) == 0 {
					return true
				}
				continue
			}

			mmsgWConn.writeMsgvec = mmsgWConn.writeMsgvec[n:]

			if len(mmsgWConn.writeMsgvec) == 0 {
				return true
			}

			// Short-write optimization:
			//
			// According to tokio, not writing the full msgvec is sufficient to show
			// that the socket buffer is full. Previous tests also showed that this is
			// faster than immediately trying to write again.
			//
			// Do keep in mind that this is not how the Go runtime handles writes though.

			// sendmmsg(2) sends up to UIO_MAXIOV (1024) messages per call.
			if n == 1024 {
				continue
			}

			return false
		}
	}

	return &mmsgWConn
}

// ReadMsgs reads as many messages as possible into the given msgvec
// and returns the number of messages read or an error.
func (c *MmsgRConn) ReadMsgs(msgvec []Mmsghdr, flags int) (int, error) {
	c.readMsgvec = msgvec
	c.readFlags = flags
	c.readN = 0
	c.readErr = nil
	if err := c.rawConn.Read(c.rawReadFunc); err != nil {
		return 0, err
	}
	return c.readN, c.readErr
}

// WriteMsgs writes all messages in the given msgvec and returns the last encountered error.
func (c *MmsgWConn) WriteMsgs(msgvec []Mmsghdr, flags int) error {
	c.writeMsgvec = msgvec
	c.writeFlags = flags
	c.writeErrno = 0
	if err := c.rawConn.Write(c.rawWriteFunc); err != nil {
		return err
	}
	if c.writeErrno != 0 {
		return os.NewSyscallError("sendmmsg", c.writeErrno)
	}
	return nil
}

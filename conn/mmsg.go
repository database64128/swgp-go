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
	writeErr     error
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
		n, errno := sendmmsg(int(fd), mmsgWConn.writeMsgvec, mmsgWConn.writeFlags)
		switch errno {
		case 0:
		case syscall.EAGAIN:
			return false
		default:
			mmsgWConn.writeErr = os.NewSyscallError("sendmmsg", errno)
			n = 1
		}
		mmsgWConn.writeMsgvec = mmsgWConn.writeMsgvec[n:]
		// According to tokio, not writing the full msgvec is sufficient to show
		// that the socket buffer is full. Previous tests also showed that this is
		// faster than immediately trying to write again.
		//
		// Do keep in mind that this is not how the Go runtime handles writes though.
		return len(mmsgWConn.writeMsgvec) == 0
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
	c.writeErr = nil
	if err := c.rawConn.Write(c.rawWriteFunc); err != nil {
		return err
	}
	return c.writeErr
}

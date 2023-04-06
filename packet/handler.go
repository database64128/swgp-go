// Package packet contains types and methods that transform WireGuard packets.
package packet

import "errors"

const (
	WireGuardMessageTypeHandshakeInitiation  = 1
	WireGuardMessageTypeHandshakeResponse    = 2
	WireGuardMessageTypeHandshakeCookieReply = 3
	WireGuardMessageTypeData                 = 4

	WireGuardMessageLengthHandshakeInitiation  = 148
	WireGuardMessageLengthHandshakeResponse    = 92
	WireGuardMessageLengthHandshakeCookieReply = 64
)

var (
	ErrPacketSize    = errors.New("packet is too big or too small to be processed")
	ErrPayloadLength = errors.New("payload length field value is out of range")
)

// Headroom reports the amount of extra space required in read/write buffers besides the payload.
type Headroom struct {
	// Front is the minimum space required at the beginning of the buffer before payload.
	Front int

	// Rear is the minimum space required at the end of the buffer after payload.
	Rear int
}

type HandlerErr struct {
	Err     error
	Message string
}

func (e *HandlerErr) Unwrap() error {
	return e.Err
}

func (e *HandlerErr) Error() string {
	if e.Message == "" {
		return e.Err.Error()
	}
	return e.Message
}

// Handler encrypts WireGuard packets and decrypts swgp packets.
type Handler interface {
	// Headroom returns the amount of extra space required in read/write buffers besides the payload.
	Headroom() Headroom

	// EncryptZeroCopy encrypts a WireGuard packet and returns a swgp packet without copying or incurring any allocations.
	//
	// The WireGuard packet starts at buf[wgPacketStart] and its length is specified by wgPacketLength.
	// The returned swgp packet starts at buf[swgpPacketStart] and its length is specified by swgpPacketLength.
	//
	// buf must have at least FrontOverhead() bytes before and RearOverhead() bytes after the WireGuard packet.
	// In other words, start must not be less than FrontOverhead(), len(buf) must not be less than start + length + RearOverhead().
	EncryptZeroCopy(buf []byte, wgPacketStart, wgPacketLength int) (swgpPacketStart, swgpPacketLength int, err error)

	// DecryptZeroCopy decrypts a swgp packet and returns a WireGuard packet without copying or incurring any allocations.
	//
	// The swgp packet starts at buf[swgpPacketStart] and its length is specified by swgpPacketLength.
	// The returned WireGuard packet starts at buf[wgPacketStart] and its length is specified by wgPacketLength.
	DecryptZeroCopy(buf []byte, swgpPacketStart, swgpPacketLength int) (wgPacketStart, wgPacketLength int, err error)
}

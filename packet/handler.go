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
	// FrontOverhead returns the headroom to reserve in buffer before payload.
	FrontOverhead() int

	// RearOverhead returns the headroom to reserve in buffer after payload.
	RearOverhead() int

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

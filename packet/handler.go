// Package packet contains types and methods that transform WireGuard packets.
package packet

const (
	WireGuardMessageTypeHandshakeInitiation  = 1
	WireGuardMessageTypeHandshakeResponse    = 2
	WireGuardMessageTypeHandshakeCookieReply = 3
	WireGuardMessageTypeData                 = 4

	WireGuardMessageLengthHandshakeInitiation  = 148
	WireGuardMessageLengthHandshakeResponse    = 92
	WireGuardMessageLengthHandshakeCookieReply = 64
)

// Handler encrypts WireGuard packets and decrypts swgp packets.
type Handler interface {
	// FrontOverhead returns the headroom to reserve in buffer before payload.
	FrontOverhead() int

	// RearOverhead returns the headroom to reserve in buffer after payload.
	RearOverhead() int

	// EncryptZeroCopy encrypts a WireGuard packet and returns a swgp packet
	// without copying or incurring any allocations.
	//
	// buf must have at least FrontOverhead() bytes before and RearOverhead() bytes
	// after the WireGuard packet.
	//
	// In other words, start must not be less than FrontOverhead(),
	// len(buf) - start - max(length, maxPacketLen) must not be less than RearOverhead().
	//
	// length is allowed to be greater than maxPacketLen (IP fragmentation).
	//
	// maxPacketLen is the maximum payload length of a single unfragmented UDP packet.
	//
	// For IPv4, maxPacketLen = MTU - 20 (IPv4 header) - 8 (UDP header).
	//
	// For IPv6, maxPacketLen = MTU - 40 (IPv6 header) - 8 (UDP header).
	EncryptZeroCopy(buf []byte, start, length, maxPacketLen int) (swgpPacket []byte, err error)

	// DecryptZeroCopy decrypts a swgp packet and returns a WireGuard packet
	// without copying or incurring any allocations.
	DecryptZeroCopy(swgpPacket []byte) (wgPacket []byte, err error)
}

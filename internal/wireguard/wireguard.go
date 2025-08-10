// Package wireguard provides constants related to the WireGuard protocol.
package wireguard

import "time"

const (
	MessageTypeHandshakeInitiation  = 1
	MessageTypeHandshakeResponse    = 2
	MessageTypeHandshakeCookieReply = 3
	MessageTypeData                 = 4

	MessageLengthHandshakeInitiation  = 148
	MessageLengthHandshakeResponse    = 92
	MessageLengthHandshakeCookieReply = 64

	DataPacketOverhead = 32

	// Data packets are padded such that the length is always a multiple of 16.
	DataPacketLengthMask = 0xFFF0

	// RejectAfterTime is the maximum lifetime of a session.
	RejectAfterTime = 180 * time.Second
)

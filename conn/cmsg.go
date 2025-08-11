package conn

import "net/netip"

// SocketControlMessageBufferSize specifies the buffer size for receiving socket control messages.
const SocketControlMessageBufferSize = socketControlMessageBufferSize

// SocketControlMessage contains information that can be parsed from or put into socket control messages.
//
// Fields of [Pktinfo] are manually embedded to avoid wasting space.
type SocketControlMessage struct {
	// PktinfoAddr is the IP address of the network interface the packet was received on, or to send the packet from.
	PktinfoAddr netip.Addr

	// PktinfoIfindex is the index of the network interface the packet was received on, or to send the packet from.
	PktinfoIfindex uint32

	// SegmentSize is the UDP GRO/GSO segment size.
	SegmentSize uint32
}

// ParseSocketControlMessage parses a sequence of socket control messages and returns the parsed information.
func ParseSocketControlMessage(cmsg []byte) (m SocketControlMessage, err error) {
	return parseSocketControlMessage(cmsg)
}

// AppendTo appends the socket control message to the buffer.
func (m SocketControlMessage) AppendTo(b []byte) []byte {
	return m.appendTo(b)
}

// Pktinfo represents packet information as specified in RFC 3542.
//
// For received packets, it contains the destination IP address and the arriving interface index.
//
// For outgoing packets, it can specify the source IP address and the outgoing interface index.
type Pktinfo struct {
	// Addr is the IP address of the network interface the packet was received on, or to send the packet from.
	Addr netip.Addr

	// Ifindex is the index of the network interface the packet was received on, or to send the packet from.
	Ifindex uint32
}

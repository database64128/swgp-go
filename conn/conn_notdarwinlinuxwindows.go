//go:build !darwin && !linux && !windows

package conn

import "net/netip"

// SocketControlMessageBufferSize specifies the buffer size for receiving socket control messages.
const SocketControlMessageBufferSize = 0

// ParsePktinfoCmsg parses a single socket control message of type IP_PKTINFO or IPV6_PKTINFO,
// and returns the IP address and index of the network interface the packet was received from,
// or an error.
//
// This function is only implemented for Linux, macOS and Windows. On other platforms, this is a no-op.
func ParsePktinfoCmsg(cmsg []byte) (netip.Addr, uint32, error) {
	return netip.Addr{}, 0, nil
}

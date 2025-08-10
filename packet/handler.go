// Package packet provides implementations of packet handlers that transform WireGuard packets.
package packet

// Handler encrypts WireGuard packets and decrypts swgp packets.
type Handler interface {
	// Encrypt encrypts wgPacket and appends the result to dst, returning the updated slice.
	//
	// The remaining capacity of dst must not overlap wgPacket.
	Encrypt(dst, wgPacket []byte) ([]byte, error)

	// Decrypt decrypts swgpPacket and appends the result to dst, returning the updated slice.
	//
	// The remaining capacity of dst must not overlap swgpPacket.
	Decrypt(dst, swgpPacket []byte) ([]byte, error)

	// Overhead returns the number of bytes that should be subtracted from the WireGuard tunnel's MTU.
	Overhead() int

	// WithMaxPacketSize returns a new Handler with the given maximum packet size.
	WithMaxPacketSize(maxPacketSize int) Handler
}

// Package swgp implements a simple proxy protocol
// with minimal overhead for WireGuard traffic.
//
// There are currently 2 proxy modes:
//
// 1. Zero overhead: Simply AES encrypt the first 16 bytes of all packets.
// Handshake packets (message type 1, 2, 3) are also randomly padded to look like normal traffic.
//
// 2. Paranoid: Pad all types of packets without exceeding MTU, then XChaCha20-Poly1305 encrypt the whole packet.
// We pad data packets because:
//
// - The length of a WireGuard data packet is always a multiple of 16.
//
// - Many IPv6 websites cap their outgoing MTU to 1280 for maximum compatibility.
package swgp

package packet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	mrand "math/rand"

	"lukechampine.com/blake3"
)

// zeroOverheadHandler encrypts and decrypts the first 16 bytes of packets
// using an AES block cipher.
// Handshake packets (message type 1, 2, 3) are randomly padded to look like normal traffic.
//
// zeroOverheadHandler implements the Handler interface.
type zeroOverheadHandler struct {
	cb        cipher.Block
	blake3xof *blake3.OutputReader
}

// NewZeroOverheadHandler creates a zero-overhead handler that
// uses the given PSK to encrypt and decrypt packets.
func NewZeroOverheadHandler(psk []byte) (Handler, error) {
	cb, err := aes.NewCipher(psk)
	if err != nil {
		return nil, err
	}

	hKey := make([]byte, 32)
	_, err = rand.Read(hKey)
	if err != nil {
		return nil, err
	}
	h := blake3.New(1024, hKey)

	return &zeroOverheadHandler{
		cb:        cb,
		blake3xof: h.XOF(),
	}, nil
}

// FrontOverhead implements the Handler FrontOverhead method.
func (h *zeroOverheadHandler) FrontOverhead() int {
	return 0
}

// RearOverhead implements the Handler RearOverhead method.
func (h *zeroOverheadHandler) RearOverhead() int {
	return 0
}

// EncryptZeroCopy implements the Handler EncryptZeroCopy method.
func (h *zeroOverheadHandler) EncryptZeroCopy(buf []byte, start, length, maxPacketLen int) (swgpPacket []byte, err error) {
	var paddingLen int

	// Add padding only if:
	// - Packet is handshake.
	// - We have room for padding.
	switch buf[start] {
	case WireGuardMessageTypeHandshakeInitiation, WireGuardMessageTypeHandshakeResponse, WireGuardMessageTypeHandshakeCookieReply:
		if maxPacketLen > length {
			paddingLen = mrand.Intn(maxPacketLen - length + 1)
		}
	}

	swgpPacket = buf[start : start+length+paddingLen]

	// Encrypt first 16 bytes.
	h.cb.Encrypt(swgpPacket[:16], swgpPacket[:16])

	// Add padding.
	if paddingLen > 0 {
		padding := swgpPacket[length:]
		_, err = h.blake3xof.Read(padding)
	}

	return
}

// DecryptZeroCopy implements the Handler DecryptZeroCopy method.
func (h *zeroOverheadHandler) DecryptZeroCopy(swgpPacket []byte) (wgPacket []byte, err error) {
	// Decrypt first 16 bytes.
	h.cb.Decrypt(swgpPacket[:16], swgpPacket[:16])

	// Hide padding.
	switch swgpPacket[0] {
	case WireGuardMessageTypeHandshakeInitiation:
		wgPacket = swgpPacket[:WireGuardMessageLengthHandshakeInitiation]
	case WireGuardMessageTypeHandshakeResponse:
		wgPacket = swgpPacket[:WireGuardMessageLengthHandshakeResponse]
	case WireGuardMessageTypeHandshakeCookieReply:
		wgPacket = swgpPacket[:WireGuardMessageLengthHandshakeCookieReply]
	default:
		wgPacket = swgpPacket
	}

	return
}

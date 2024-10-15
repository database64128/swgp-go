package packet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand/v2"

	"github.com/database64128/swgp-go/slicehelper"
	"golang.org/x/crypto/chacha20poly1305"
)

// zeroOverheadHandler encrypts and decrypts the first 16 bytes of packets using an AES block cipher.
// The remainder of handshake packets (message type 1, 2, 3) are also randomly padded and encrypted
// using an XChaCha20-Poly1305 AEAD cipher to blend into normal traffic.
//
//	swgpPacket := aes(wgDataPacket[:16]) + wgDataPacket[16:]
//	swgpPacket := aes(wgHandshakePacket[:16]) + AEAD_Seal(payload + padding + u16be payload length) + 24B nonce
//
// zeroOverheadHandler implements [Handler].
type zeroOverheadHandler struct {
	cb                     cipher.Block
	aead                   cipher.AEAD
	maxPacketSize          int
	maxHandshakePacketSize int
}

// NewZeroOverheadHandler creates a zero-overhead handler that
// uses the given PSK to encrypt and decrypt packets.
func NewZeroOverheadHandler(psk []byte, maxPacketSize int) (Handler, error) {
	cb, err := aes.NewCipher(psk)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(psk)
	if err != nil {
		return nil, err
	}

	return &zeroOverheadHandler{
		cb:                     cb,
		aead:                   aead,
		maxPacketSize:          maxPacketSize,
		maxHandshakePacketSize: zeroOverheadHandlerMaxHandshakePacketSizeFromMaxPacketSize(maxPacketSize),
	}, nil
}

// WithMaxPacketSize implements [Handler.WithMaxPacketSize].
func (h *zeroOverheadHandler) WithMaxPacketSize(maxPacketSize int) Handler {
	if h.maxPacketSize == maxPacketSize {
		return h
	}
	return &zeroOverheadHandler{
		cb:                     h.cb,
		aead:                   h.aead,
		maxHandshakePacketSize: zeroOverheadHandlerMaxHandshakePacketSizeFromMaxPacketSize(maxPacketSize),
	}
}

func zeroOverheadHandlerMaxHandshakePacketSizeFromMaxPacketSize(maxPacketSize int) int {
	return maxPacketSize - 2 - chacha20poly1305.Overhead - chacha20poly1305.NonceSizeX
}

// Encrypt implements [Handler.Encrypt].
func (h *zeroOverheadHandler) Encrypt(dst, wgPacket []byte) ([]byte, error) {
	// Return packets smaller than a single AES block unmodified.
	if len(wgPacket) < aes.BlockSize {
		return append(dst, wgPacket...), nil
	}

	dst, b := slicehelper.Extend(dst, len(wgPacket))

	// Save message type.
	messageType := wgPacket[0]

	// Encrypt the first AES block.
	h.cb.Encrypt(b, wgPacket)

	// Copy the remaining bytes.
	remainingPayloadSize := copy(b[aes.BlockSize:], wgPacket[aes.BlockSize:])

	// We are done with non-handshake packets.
	switch messageType {
	case WireGuardMessageTypeHandshakeInitiation, WireGuardMessageTypeHandshakeResponse, WireGuardMessageTypeHandshakeCookieReply:
	default:
		return dst, nil
	}

	paddingHeadroom := h.maxHandshakePacketSize - len(wgPacket)
	if paddingHeadroom < 0 || remainingPayloadSize > 65535 {
		return nil, fmt.Errorf("handshake packet (type %d) is too large (%d bytes)", messageType, len(wgPacket))
	}

	var paddingLen int
	if paddingHeadroom > 0 {
		paddingLen = 1 + mrand.IntN(paddingHeadroom)
	}

	dst, b = slicehelper.Extend(dst, paddingLen+2+chacha20poly1305.Overhead+chacha20poly1305.NonceSizeX)

	// Put payload length.
	binary.BigEndian.PutUint16(b[paddingLen:], uint16(remainingPayloadSize))

	// Put nonce.
	nonce := dst[len(dst)-chacha20poly1305.NonceSizeX:]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Seal the remainder in-place.
	plaintextEnd := len(dst) - chacha20poly1305.NonceSizeX - chacha20poly1305.Overhead
	plaintextStart := plaintextEnd - 2 - paddingLen - remainingPayloadSize
	plaintext := dst[plaintextStart:plaintextEnd]
	_ = h.aead.Seal(plaintext[:0], nonce, plaintext, nil)

	return dst, nil
}

// Decrypt implements [Handler.Decrypt].
func (h *zeroOverheadHandler) Decrypt(dst, swgpPacket []byte) ([]byte, error) {
	// Return packets smaller than a single AES block unmodified.
	if len(swgpPacket) < aes.BlockSize {
		return append(dst, swgpPacket...), nil
	}

	dst, b := slicehelper.Extend(dst, aes.BlockSize)

	// Decrypt the first AES block.
	h.cb.Decrypt(b, swgpPacket)

	// For non-handshake packets, copy the remaining bytes and be done with it.
	switch b[0] {
	case WireGuardMessageTypeHandshakeInitiation, WireGuardMessageTypeHandshakeResponse, WireGuardMessageTypeHandshakeCookieReply:
	default:
		return append(dst, swgpPacket[aes.BlockSize:]...), nil
	}

	if len(swgpPacket) < aes.BlockSize+2+chacha20poly1305.Overhead+chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("invalid swgp handshake packet length %d", len(swgpPacket))
	}

	dstLen := len(dst)

	// Open the remainder into dst.
	nonceStart := len(swgpPacket) - chacha20poly1305.NonceSizeX
	nonce := swgpPacket[nonceStart:]
	ciphertext := swgpPacket[aes.BlockSize:nonceStart]
	dst, err := h.aead.Open(dst, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// Read and validate payload length.
	paddingEnd := len(dst) - 2
	remainingPayloadSize := int(binary.BigEndian.Uint16(dst[paddingEnd:]))
	dstLen += remainingPayloadSize
	if dstLen > paddingEnd {
		return nil, fmt.Errorf("invalid swgp handshake packet payload length %d", remainingPayloadSize)
	}

	return dst[:dstLen], nil
}

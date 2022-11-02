package packet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// zeroOverheadHandshakePacketMinimumOverhead is the minimum overhead of a handshake packet encrypted by zeroOverheadHandler.
// Additional overhead is the random-length padding.
const zeroOverheadHandshakePacketMinimumOverhead = 2 + chacha20poly1305.Overhead + chacha20poly1305.NonceSizeX

// zeroOverheadHandler encrypts and decrypts the first 16 bytes of packets using an AES block cipher.
// The remainder of handshake packets (message type 1, 2, 3) are also randomly padded and encrypted
// using an XChaCha20-Poly1305 AEAD cipher to blend into normal traffic.
//
//	swgpPacket := aes(wgDataPacket[:16]) + wgDataPacket[16:]
//	swgpPacket := aes(wgHandshakePacket[:16]) + AEAD_Seal(payload + padding + u16be payload length) + 24B nonce
//
// zeroOverheadHandler implements the Handler interface.
type zeroOverheadHandler struct {
	cb   cipher.Block
	aead cipher.AEAD
	rng  *mrand.Rand
}

// NewZeroOverheadHandler creates a zero-overhead handler that
// uses the given PSK to encrypt and decrypt packets.
func NewZeroOverheadHandler(psk []byte) (Handler, error) {
	cb, err := aes.NewCipher(psk)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(psk)
	if err != nil {
		return nil, err
	}

	return &zeroOverheadHandler{
		cb:   cb,
		aead: aead,
		rng:  mrand.New(mrand.NewSource(time.Now().UnixNano())),
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
func (h *zeroOverheadHandler) EncryptZeroCopy(buf []byte, wgPacketStart, wgPacketLength int) (swgpPacketStart, swgpPacketLength int, err error) {
	swgpPacketStart = wgPacketStart
	swgpPacketLength = wgPacketLength

	// Skip small packets.
	if wgPacketLength < 16 {
		return
	}

	// Save message type.
	messageType := buf[wgPacketStart]

	// Encrypt first 16 bytes.
	h.cb.Encrypt(buf[wgPacketStart:], buf[wgPacketStart:])

	// We are done with non-handshake packets.
	switch messageType {
	case WireGuardMessageTypeHandshakeInitiation, WireGuardMessageTypeHandshakeResponse, WireGuardMessageTypeHandshakeCookieReply:
	default:
		return
	}

	// Return error if packet is so big that buffer has no room for AEAD overhead.
	rearHeadroom := len(buf) - wgPacketStart - wgPacketLength
	paddingHeadroom := rearHeadroom - 2 - chacha20poly1305.Overhead - chacha20poly1305.NonceSizeX
	if paddingHeadroom < 0 {
		err = &HandlerErr{ErrPacketSize, fmt.Sprintf("handshake packet (length %d) is too large to process in buffer (length %d)", wgPacketLength, len(buf))}
		return
	}

	var paddingLen int
	if paddingHeadroom > 0 {
		paddingLen = h.rng.Intn(paddingHeadroom) + 1
	}

	swgpPacketLength += paddingLen + zeroOverheadHandshakePacketMinimumOverhead

	// Calculate offsets.
	plaintextStart := wgPacketStart + 16
	payloadLengthBufStart := wgPacketStart + wgPacketLength + paddingLen
	plaintextEnd := payloadLengthBufStart + 2
	nonceStart := plaintextEnd + chacha20poly1305.Overhead
	nonceEnd := nonceStart + chacha20poly1305.NonceSizeX

	// Write payload length.
	payloadLength := wgPacketLength - 16
	payloadLengthBuf := buf[payloadLengthBufStart:plaintextEnd]
	binary.BigEndian.PutUint16(payloadLengthBuf, uint16(payloadLength))

	plaintext := buf[plaintextStart:plaintextEnd]
	nonce := buf[nonceStart:nonceEnd]
	_, err = rand.Read(nonce)
	if err != nil {
		return
	}

	h.aead.Seal(plaintext[:0], nonce, plaintext, nil)
	return
}

// DecryptZeroCopy implements the Handler DecryptZeroCopy method.
func (h *zeroOverheadHandler) DecryptZeroCopy(buf []byte, swgpPacketStart, swgpPacketLength int) (wgPacketStart, wgPacketLength int, err error) {
	wgPacketStart = swgpPacketStart
	wgPacketLength = swgpPacketLength

	// Skip small packets.
	if swgpPacketLength < 16 {
		return
	}

	// Decrypt first 16 bytes.
	h.cb.Decrypt(buf[swgpPacketStart:], buf[swgpPacketStart:])

	// We are done with non-handshake and short handshake packets.
	switch buf[swgpPacketStart] {
	case WireGuardMessageTypeHandshakeInitiation, WireGuardMessageTypeHandshakeResponse, WireGuardMessageTypeHandshakeCookieReply:
		if swgpPacketLength < 16+zeroOverheadHandshakePacketMinimumOverhead {
			err = &HandlerErr{ErrPacketSize, fmt.Sprintf("swgp packet too short: %d", swgpPacketLength)}
			return
		}
	default:
		return
	}

	// Calculate offsets.
	nonceEnd := swgpPacketStart + swgpPacketLength
	nonceStart := nonceEnd - chacha20poly1305.NonceSizeX
	plaintextEnd := nonceStart - chacha20poly1305.Overhead
	payloadLengthBufStart := plaintextEnd - 2
	plaintextStart := swgpPacketStart + 16

	ciphertext := buf[plaintextStart:nonceStart]
	nonce := buf[nonceStart:nonceEnd]
	_, err = h.aead.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return
	}

	// Read and validate payload length.
	payloadLengthBuf := buf[payloadLengthBufStart:plaintextEnd]
	payloadLength := int(binary.BigEndian.Uint16(payloadLengthBuf))
	if payloadLength > payloadLengthBufStart-plaintextStart {
		err = &HandlerErr{ErrPayloadLength, fmt.Sprintf("payload length field value %d is out of range", payloadLength)}
		return
	}

	wgPacketLength = 16 + payloadLength
	return
}

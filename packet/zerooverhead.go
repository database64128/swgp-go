package packet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand/v2"
	"slices"
	"time"

	"github.com/database64128/swgp-go/internal/replay"
	"github.com/database64128/swgp-go/internal/wireguard"
	"golang.org/x/crypto/chacha20poly1305"
)

// zeroOverheadHandler encrypts and decrypts the first 16 bytes of packets using an AES block cipher.
// The remainder of handshake packets (message type 1, 2, 3) are also randomly padded and encrypted
// using an XChaCha20-Poly1305 AEAD cipher to blend into normal traffic.
//
//	swgpPacket := aes(wgDataPacket[:16]) + wgDataPacket[16:]
//	swgpPacket := aes(wgHandshakePacket[:16]) + AEAD_Seal(plaintext: payload + padding + u16be payload length) + 24B nonce
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
		maxPacketSize:          maxPacketSize,
		maxHandshakePacketSize: zeroOverheadHandlerMaxHandshakePacketSizeFromMaxPacketSize(maxPacketSize),
	}
}

func zeroOverheadHandlerMaxHandshakePacketSizeFromMaxPacketSize(maxPacketSize int) int {
	return maxPacketSize - 2 - chacha20poly1305.Overhead - chacha20poly1305.NonceSizeX
}

// Overhead implements [Handler.Overhead].
func (h *zeroOverheadHandler) Overhead() int {
	return 0
}

// Encrypt implements [Handler.Encrypt].
func (h *zeroOverheadHandler) Encrypt(dst, wgPacket []byte) ([]byte, error) {
	// Return packets smaller than a single AES block unmodified.
	if len(wgPacket) < aes.BlockSize {
		return append(dst, wgPacket...), nil
	}

	dstLen := len(dst)
	dst = slices.Grow(dst, len(wgPacket))[:dstLen+aes.BlockSize]
	b := dst[dstLen:]
	plaintextStart := len(dst)

	// Save message type.
	messageType := wgPacket[0]

	// Encrypt the first AES block.
	h.cb.Encrypt(b, wgPacket)

	// Append the remaining payload.
	remainingPayload := wgPacket[aes.BlockSize:]
	dst = append(dst, remainingPayload...)

	// We are done with non-handshake packets.
	switch messageType {
	case wireguard.MessageTypeHandshakeInitiation, wireguard.MessageTypeHandshakeResponse, wireguard.MessageTypeHandshakeCookieReply:
	default:
		return dst, nil
	}

	paddingHeadroom := h.maxHandshakePacketSize - len(wgPacket)
	if paddingHeadroom < 0 || len(remainingPayload) > 65535 {
		return nil, fmt.Errorf("handshake packet (type %d) is too large (%d bytes)", messageType, len(wgPacket))
	}

	var paddingLen int
	if paddingHeadroom > 0 {
		paddingLen = 1 + mrand.IntN(paddingHeadroom)
	}

	dstLen = len(dst)
	dst = slices.Grow(dst, paddingLen+2+chacha20poly1305.Overhead+chacha20poly1305.NonceSizeX)[:dstLen+paddingLen]

	// Append payload length.
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(remainingPayload)))

	// Put nonce.
	nonceStart := len(dst) + chacha20poly1305.Overhead
	nonceEnd := nonceStart + chacha20poly1305.NonceSizeX
	nonce := dst[nonceStart:nonceEnd]
	rand.Read(nonce)

	// Seal the remainder in-place.
	dst = h.aead.Seal(dst[:plaintextStart], nonce, dst[plaintextStart:], nil)

	return dst[:len(dst)+chacha20poly1305.NonceSizeX], nil
}

// Decrypt implements [Handler.Decrypt].
func (h *zeroOverheadHandler) Decrypt(dst, swgpPacket []byte) ([]byte, error) {
	// Return packets smaller than a single AES block unmodified.
	if len(swgpPacket) < aes.BlockSize {
		return append(dst, swgpPacket...), nil
	}

	dstLen := len(dst)
	dst = slices.Grow(dst, aes.BlockSize)[:dstLen+aes.BlockSize]
	b := dst[dstLen:]

	// Decrypt the first AES block.
	h.cb.Decrypt(b, swgpPacket)

	// For non-handshake packets, copy the remaining bytes and be done with it.
	switch b[0] {
	case wireguard.MessageTypeHandshakeInitiation, wireguard.MessageTypeHandshakeResponse, wireguard.MessageTypeHandshakeCookieReply:
	default:
		return append(dst, swgpPacket[aes.BlockSize:]...), nil
	}

	if len(swgpPacket) < aes.BlockSize+2+chacha20poly1305.Overhead+chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("invalid swgp handshake packet length %d", len(swgpPacket))
	}

	dstLen = len(dst)

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

// zeroOverhead2026Handler encrypts and decrypts the first 16 bytes of packets using an AES block cipher.
// The remainder of handshake packets (message type 1, 2, 3) are also randomly padded and encrypted
// using an XChaCha20-Poly1305 AEAD cipher to blend into normal traffic.
//
//	swgpPacket := aes(wgDataPacket[:16]) + wgDataPacket[16:]
//	swgpPacket := aes(wgHandshakePacket[:16]) + AEAD_Seal(plaintext: payload + padding + u16le payload length + i64le unix epoch, additionalData: wgHandshakePacket[:16]) + 24B nonce
//
// Compared to zeroOverheadHandler, zeroOverhead2026Handler adds a unix epoch timestamp to the handshake packet payload
// and includes the first 16 bytes of the handshake packet as additional data in the AEAD construction.
// This allows replay protection without sacrificing "zero overhead" for data packets.
//
// zeroOverhead2026Handler implements [Handler].
type zeroOverhead2026Handler struct {
	cb                     cipher.Block
	aead                   cipher.AEAD
	pool                   replay.NoncePool
	maxPacketSize          int
	maxHandshakePacketSize int
}

// NewZeroOverhead2026Handler creates a zero-overhead handler that
// uses the given PSK to encrypt and decrypt packets.
func NewZeroOverhead2026Handler(psk []byte, maxPacketSize int) (Handler, error) {
	cb, err := aes.NewCipher(psk)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(psk)
	if err != nil {
		return nil, err
	}

	return &zeroOverhead2026Handler{
		cb:                     cb,
		aead:                   aead,
		maxPacketSize:          maxPacketSize,
		maxHandshakePacketSize: zeroOverhead2026HandlerMaxHandshakePacketSizeFromMaxPacketSize(maxPacketSize),
	}, nil
}

// WithMaxPacketSize implements [Handler.WithMaxPacketSize].
func (h *zeroOverhead2026Handler) WithMaxPacketSize(maxPacketSize int) Handler {
	if h.maxPacketSize == maxPacketSize {
		return h
	}
	return &zeroOverhead2026Handler{
		cb:                     h.cb,
		aead:                   h.aead,
		maxPacketSize:          maxPacketSize,
		maxHandshakePacketSize: zeroOverhead2026HandlerMaxHandshakePacketSizeFromMaxPacketSize(maxPacketSize),
	}
}

const zeroOverhead2026HandlerHandshakeOverhead = 2 + 8 + chacha20poly1305.Overhead + chacha20poly1305.NonceSizeX

func zeroOverhead2026HandlerMaxHandshakePacketSizeFromMaxPacketSize(maxPacketSize int) int {
	return maxPacketSize - zeroOverhead2026HandlerHandshakeOverhead
}

// Overhead implements [Handler.Overhead].
func (h *zeroOverhead2026Handler) Overhead() int {
	return 0
}

// Encrypt implements [Handler.Encrypt].
func (h *zeroOverhead2026Handler) Encrypt(dst, wgPacket []byte) ([]byte, error) {
	// Return packets smaller than a single AES block unmodified.
	if len(wgPacket) < aes.BlockSize {
		return append(dst, wgPacket...), nil
	}

	dstLen := len(dst)
	dst = slices.Grow(dst, len(wgPacket))[:dstLen+aes.BlockSize]
	b := dst[dstLen:]
	plaintextStart := len(dst)

	// Save message type.
	messageType := wgPacket[0]

	// Encrypt the first AES block.
	h.cb.Encrypt(b, wgPacket)

	// Append the remaining payload.
	remainingPayload := wgPacket[aes.BlockSize:]
	dst = append(dst, remainingPayload...)

	// We are done with non-handshake packets.
	switch messageType {
	case wireguard.MessageTypeHandshakeInitiation, wireguard.MessageTypeHandshakeResponse, wireguard.MessageTypeHandshakeCookieReply:
	default:
		return dst, nil
	}

	paddingHeadroom := h.maxHandshakePacketSize - len(wgPacket)
	if paddingHeadroom < 0 || len(remainingPayload) > 65535 {
		return nil, fmt.Errorf("handshake packet (type %d) is too large (%d bytes)", messageType, len(wgPacket))
	}

	var paddingLen int
	if paddingHeadroom > 0 {
		paddingLen = 1 + mrand.IntN(paddingHeadroom)
	}

	dstLen = len(dst)
	dst = slices.Grow(dst, paddingLen+zeroOverhead2026HandlerHandshakeOverhead)[:dstLen+paddingLen]

	// Append payload length.
	dst = binary.LittleEndian.AppendUint16(dst, uint16(len(remainingPayload)))

	// Append unix epoch timestamp.
	dst = binary.LittleEndian.AppendUint64(dst, uint64(time.Now().Unix()))

	// Put nonce.
	nonceStart := len(dst) + chacha20poly1305.Overhead
	nonceEnd := nonceStart + chacha20poly1305.NonceSizeX
	nonce := dst[nonceStart:nonceEnd]
	rand.Read(nonce)

	// Seal the remainder in-place.
	dst = h.aead.Seal(dst[:plaintextStart], nonce, dst[plaintextStart:], wgPacket[:aes.BlockSize])

	return dst[:len(dst)+chacha20poly1305.NonceSizeX], nil
}

// Decrypt implements [Handler.Decrypt].
func (h *zeroOverhead2026Handler) Decrypt(dst, swgpPacket []byte) ([]byte, error) {
	// Return packets smaller than a single AES block unmodified.
	if len(swgpPacket) < aes.BlockSize {
		return append(dst, swgpPacket...), nil
	}

	dstLen := len(dst)
	dst = slices.Grow(dst, aes.BlockSize)[:dstLen+aes.BlockSize]
	b := dst[dstLen:]

	// Decrypt the first AES block.
	h.cb.Decrypt(b, swgpPacket)

	// For non-handshake packets, copy the remaining bytes and be done with it.
	switch b[0] {
	case wireguard.MessageTypeHandshakeInitiation, wireguard.MessageTypeHandshakeResponse, wireguard.MessageTypeHandshakeCookieReply:
	default:
		return append(dst, swgpPacket[aes.BlockSize:]...), nil
	}

	if len(swgpPacket) < aes.BlockSize+zeroOverhead2026HandlerHandshakeOverhead {
		return nil, fmt.Errorf("invalid swgp handshake packet length %d", len(swgpPacket))
	}

	dstLen = len(dst)

	// Do a quick nonce check.
	nonceStart := len(swgpPacket) - chacha20poly1305.NonceSizeX
	nonce := swgpPacket[nonceStart:]
	nonceKey := replay.Nonce(nonce)
	if h.pool.TryContains(nonceKey) {
		return nil, replay.ErrRepeatedNonce
	}

	// Open the remainder into dst.
	ciphertext := swgpPacket[aes.BlockSize:nonceStart]
	dst, err := h.aead.Open(dst, nonce, ciphertext, b[:aes.BlockSize])
	if err != nil {
		return nil, err
	}

	// Read and validate unix epoch timestamp.
	tsEpochStart := len(dst) - 8
	now := time.Now()
	if err := replay.ValidateUnixEpochTimestamp(dst[tsEpochStart:], now); err != nil {
		return nil, err
	}

	// Check and add nonce to pool.
	if !h.pool.Add(now, nonceKey) {
		return nil, replay.ErrRepeatedNonce
	}

	// Read and validate payload length.
	paddingEnd := tsEpochStart - 2
	remainingPayloadSize := int(binary.LittleEndian.Uint16(dst[paddingEnd:]))
	dstLen += remainingPayloadSize
	if dstLen > paddingEnd {
		return nil, fmt.Errorf("invalid swgp handshake packet payload length %d", remainingPayloadSize)
	}

	return dst[:dstLen], nil
}

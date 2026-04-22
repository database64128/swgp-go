package packet

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/database64128/swgp-go/internal/replay"
	"github.com/database64128/swgp-go/internal/wireguard"
	"golang.org/x/crypto/chacha20poly1305"
)

// ParanoidHandlerOverhead is the number of bytes that should be subtracted from
// the WireGuard tunnel's MTU when using the paranoid handler.
const ParanoidHandlerOverhead = chacha20poly1305.NonceSizeX + 2 + chacha20poly1305.Overhead

// paranoidHandler encrypts and decrypts whole packets using an AEAD cipher.
// All packets, irrespective of message type, are padded to the maximum packet length
// to hide any possible characteristics.
//
//	swgpPacket := 24B nonce + AEAD_Seal(u16be payload length + payload + padding)
//
// paranoidHandler implements [Handler].
type paranoidHandler struct {
	aead           cipher.AEAD
	maxPacketSize  int
	maxPayloadSize int
}

// NewParanoidHandler creates a "paranoid" handler that
// uses the given PSK to encrypt and decrypt packets.
func NewParanoidHandler(psk []byte, maxPacketSize int) (Handler, error) {
	aead, err := chacha20poly1305.NewX(psk)
	if err != nil {
		return nil, err
	}

	return &paranoidHandler{
		aead:           aead,
		maxPacketSize:  maxPacketSize,
		maxPayloadSize: paranoidHandlerMaxPayloadSizeFromMaxPacketSize(maxPacketSize),
	}, nil
}

// WithMaxPacketSize implements [Handler.WithMaxPacketSize].
func (h *paranoidHandler) WithMaxPacketSize(maxPacketSize int) Handler {
	if h.maxPacketSize == maxPacketSize {
		return h
	}
	return &paranoidHandler{
		aead:           h.aead,
		maxPacketSize:  maxPacketSize,
		maxPayloadSize: paranoidHandlerMaxPayloadSizeFromMaxPacketSize(maxPacketSize),
	}
}

func paranoidHandlerMaxPayloadSizeFromMaxPacketSize(maxPacketSize int) int {
	return min(65535, maxPacketSize-ParanoidHandlerOverhead)
}

// Overhead implements [Handler.Overhead].
func (h *paranoidHandler) Overhead() int {
	return ParanoidHandlerOverhead
}

// Encrypt implements [Handler.Encrypt].
func (h *paranoidHandler) Encrypt(dst, wgPacket []byte) ([]byte, error) {
	if len(wgPacket) > h.maxPayloadSize {
		return nil, fmt.Errorf("packet is too large: got %d bytes, want at most %d bytes", len(wgPacket), h.maxPayloadSize)
	}

	dstLen := len(dst)
	dst = slices.Grow(dst, h.maxPacketSize)[:dstLen+chacha20poly1305.NonceSizeX]
	nonce := dst[dstLen:]
	plaintext := dst[len(dst) : dstLen+h.maxPacketSize-chacha20poly1305.Overhead]

	// Put nonce.
	rand.Read(nonce)

	// Put payload length.
	binary.BigEndian.PutUint16(plaintext, uint16(len(wgPacket)))

	// Copy payload.
	_ = copy(plaintext[2:], wgPacket)

	// Seal the plaintext in-place.
	return h.aead.Seal(dst, nonce, plaintext, nil), nil
}

// Decrypt implements [Handler.Decrypt].
func (h *paranoidHandler) Decrypt(dst, swgpPacket []byte) ([]byte, error) {
	if len(swgpPacket) != h.maxPacketSize {
		return nil, fmt.Errorf("invalid packet size: got %d bytes, want %d bytes", len(swgpPacket), h.maxPacketSize)
	}

	nonce := swgpPacket[:chacha20poly1305.NonceSizeX]
	ciphertext := swgpPacket[chacha20poly1305.NonceSizeX:]

	// Open the ciphertext in-place.
	plaintext, err := h.aead.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// Read and validate payload length.
	payloadLength := int(binary.BigEndian.Uint16(plaintext))
	if len(plaintext) < 2+payloadLength {
		return nil, fmt.Errorf("invalid payload length %d", payloadLength)
	}

	return append(dst, plaintext[2:2+payloadLength]...), nil
}

// paranoid2026Handler encrypts and decrypts whole packets using an AEAD cipher.
// All packets, irrespective of message type, are padded to the maximum packet length
// to hide any possible characteristics.
//
//	swgpPacket := 24B nonce + AEAD_Seal(u16le payload length + payload(wgDataPacket) + padding)
//	swgpPacket := 24B nonce + AEAD_Seal(u16le payload length + payload(wgHandshakePacket) + i64le unix epoch + padding)
//
// Compared to paranoidHandler, paranoid2026Handler switches to little-endian encoding for the payload length and
// includes a unix epoch timestamp for handshake packets to protect against replay attacks.
//
// paranoid2026Handler implements [Handler].
type paranoid2026Handler struct {
	aead           cipher.AEAD
	pool           replay.NoncePool
	maxPacketSize  int
	maxPayloadSize int
}

// NewParanoid2026Handler creates a "paranoid" handler that
// uses the given PSK to encrypt and decrypt packets.
func NewParanoid2026Handler(psk []byte, maxPacketSize int) (Handler, error) {
	aead, err := chacha20poly1305.NewX(psk)
	if err != nil {
		return nil, err
	}

	return &paranoid2026Handler{
		aead:           aead,
		maxPacketSize:  maxPacketSize,
		maxPayloadSize: paranoidHandlerMaxPayloadSizeFromMaxPacketSize(maxPacketSize),
	}, nil
}

// WithMaxPacketSize implements [Handler.WithMaxPacketSize].
func (h *paranoid2026Handler) WithMaxPacketSize(maxPacketSize int) Handler {
	if h.maxPacketSize == maxPacketSize {
		return h
	}
	return &paranoid2026Handler{
		aead:           h.aead,
		maxPacketSize:  maxPacketSize,
		maxPayloadSize: paranoidHandlerMaxPayloadSizeFromMaxPacketSize(maxPacketSize),
	}
}

// Overhead implements [Handler.Overhead].
func (h *paranoid2026Handler) Overhead() int {
	return ParanoidHandlerOverhead
}

// Encrypt implements [Handler.Encrypt].
func (h *paranoid2026Handler) Encrypt(dst, wgPacket []byte) ([]byte, error) {
	var tsEpochSize int
	if len(wgPacket) > 0 && wgPacket[0] != wireguard.MessageTypeData {
		tsEpochSize = 8
	}
	if maxPayloadSize := h.maxPayloadSize - tsEpochSize; len(wgPacket) > maxPayloadSize {
		return nil, fmt.Errorf("packet is too large: got %d bytes, want at most %d bytes", len(wgPacket), maxPayloadSize)
	}

	dstLen := len(dst)
	dst = slices.Grow(dst, h.maxPacketSize)[:dstLen+chacha20poly1305.NonceSizeX]
	nonce := dst[dstLen:]
	plaintext := dst[len(dst) : dstLen+h.maxPacketSize-chacha20poly1305.Overhead]

	// Put nonce.
	rand.Read(nonce)

	// Put payload length.
	binary.LittleEndian.PutUint16(plaintext, uint16(len(wgPacket)))

	// Copy payload.
	_ = copy(plaintext[2:], wgPacket)

	// Put unix epoch timestamp for handshake packets.
	if tsEpochSize > 0 {
		binary.LittleEndian.PutUint64(plaintext[2+len(wgPacket):], uint64(time.Now().Unix()))
	}

	// Seal the plaintext in-place.
	return h.aead.Seal(dst, nonce, plaintext, nil), nil
}

var errHandshakeNoTimestamp = errors.New("handshake packet is missing timestamp")

// Decrypt implements [Handler.Decrypt].
func (h *paranoid2026Handler) Decrypt(dst, swgpPacket []byte) ([]byte, error) {
	if len(swgpPacket) != h.maxPacketSize {
		return nil, fmt.Errorf("invalid packet size: got %d bytes, want %d bytes", len(swgpPacket), h.maxPacketSize)
	}

	nonce := swgpPacket[:chacha20poly1305.NonceSizeX]
	ciphertext := swgpPacket[chacha20poly1305.NonceSizeX:]

	// Open the ciphertext in-place.
	plaintext, err := h.aead.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// Read and validate payload length.
	payloadLength := int(binary.LittleEndian.Uint16(plaintext))
	if len(plaintext) < 2+payloadLength {
		return nil, fmt.Errorf("invalid payload length %d", payloadLength)
	}

	payload := plaintext[2 : 2+payloadLength]

	// Validate unix epoch timestamp for handshake packets.
	if len(payload) > 0 && payload[0] != wireguard.MessageTypeData {
		tsEpochBytes := plaintext[2+payloadLength:]
		if len(tsEpochBytes) < 8 {
			return nil, errHandshakeNoTimestamp
		}
		now := time.Now()
		if err := replay.ValidateUnixEpochTimestamp(tsEpochBytes, now); err != nil {
			return nil, err
		}
		if !h.pool.Add(now, replay.Nonce(nonce)) {
			return nil, replay.ErrRepeatedNonce
		}
	}

	return append(dst, payload...), nil
}

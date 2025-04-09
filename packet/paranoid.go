package packet

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"slices"

	"golang.org/x/crypto/chacha20poly1305"
)

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
	return min(65535, maxPacketSize-chacha20poly1305.NonceSizeX-2-chacha20poly1305.Overhead)
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

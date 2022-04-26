package packet

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	mrand "math/rand"

	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"
)

// paranoidHandler encrypts and decrypts whole packets using an AEAD cipher.
// All packets, irrespective of message type, are padded up to the maximum packet length
// to hide any possible characteristics.
//
// swgpPacket := 24B nonce + AEAD_Seal(2B payload length + payload + padding)
type paranoidHandler struct {
	aead      cipher.AEAD
	blake3xof *blake3.OutputReader
}

// NewParanoidHandler creates a "paranoid" handler that
// uses the given PSK to encrypt and decrypt packets.
func NewParanoidHandler(psk []byte) (Handler, error) {
	aead, err := chacha20poly1305.NewX(psk)
	if err != nil {
		return nil, err
	}

	hKey := make([]byte, 32)
	_, err = rand.Read(hKey)
	if err != nil {
		return nil, err
	}
	h := blake3.New(24, hKey)

	return &paranoidHandler{
		aead:      aead,
		blake3xof: h.XOF(),
	}, nil
}

// FrontOverhead implements the Handler FrontOverhead method.
func (h *paranoidHandler) FrontOverhead() int {
	return chacha20poly1305.NonceSizeX + 2
}

// RearOverhead implements the Handler RearOverhead method.
func (h *paranoidHandler) RearOverhead() int {
	return chacha20poly1305.Overhead
}

// EncryptZeroCopy implements the Handler EncryptZeroCopy method.
func (h *paranoidHandler) EncryptZeroCopy(buf []byte, start, length, maxPacketLen int) (swgpPacket []byte, err error) {
	if length > math.MaxUint16 {
		return nil, fmt.Errorf("payload too long: %d is greater than 65535", length)
	}

	var paddingLen int

	if maxPaddingLen := maxPacketLen - h.FrontOverhead() - length - h.RearOverhead(); maxPaddingLen > 0 {
		paddingLen = mrand.Intn(maxPaddingLen + 1)
	}

	nonce := buf[start-chacha20poly1305.NonceSizeX-2 : start-2]
	payloadLength := buf[start-2 : start]
	plaintext := buf[start-2 : start+length+paddingLen]

	// Write random nonce.
	_, err = h.blake3xof.Read(nonce)
	if err != nil {
		return nil, err
	}

	// Write payload length.
	binary.BigEndian.PutUint16(payloadLength, uint16(length))

	// AEAD seal.
	swgpPacket = h.aead.Seal(nonce, nonce, plaintext, nil)

	return
}

// DecryptZeroCopy implements the Handler DecryptZeroCopy method.
func (h *paranoidHandler) DecryptZeroCopy(swgpPacket []byte) (wgPacket []byte, err error) {
	if len(swgpPacket) < chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("bad swgpPacket length: %d", len(swgpPacket))
	}

	nonce := swgpPacket[:chacha20poly1305.NonceSizeX]
	ciphertext := swgpPacket[chacha20poly1305.NonceSizeX:]

	// AEAD open.
	plaintext, err := h.aead.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// Read and validate payload length.
	payloadLength := plaintext[:2]
	length := int(binary.BigEndian.Uint16(payloadLength))
	if 2+length > len(plaintext) {
		return nil, fmt.Errorf("payload length %d is greater than plaintext length %d", length, len(plaintext))
	}

	wgPacket = plaintext[2 : 2+length]
	return
}

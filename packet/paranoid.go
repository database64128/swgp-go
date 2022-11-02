package packet

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	mrand "math/rand"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// paranoidHandler encrypts and decrypts whole packets using an AEAD cipher.
// All packets, irrespective of message type, are padded up to the maximum packet length
// to hide any possible characteristics.
//
//	swgpPacket := 24B nonce + AEAD_Seal(u16be payload length + payload + padding)
//
// paranoidHandler implements the Handler interface.
type paranoidHandler struct {
	aead cipher.AEAD
	rng  *mrand.Rand
}

// NewParanoidHandler creates a "paranoid" handler that
// uses the given PSK to encrypt and decrypt packets.
func NewParanoidHandler(psk []byte) (Handler, error) {
	aead, err := chacha20poly1305.NewX(psk)
	if err != nil {
		return nil, err
	}

	return &paranoidHandler{
		aead: aead,
		rng:  mrand.New(mrand.NewSource(time.Now().UnixNano())),
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
func (h *paranoidHandler) EncryptZeroCopy(buf []byte, wgPacketStart, wgPacketLength int) (swgpPacketStart, swgpPacketLength int, err error) {
	if wgPacketLength > math.MaxUint16 {
		err = &HandlerErr{ErrPacketSize, fmt.Sprintf("wg packet (length %d) is too large (greater than %d)", wgPacketLength, math.MaxUint16)}
		return
	}

	// Determine padding length.
	rearHeadroom := len(buf) - wgPacketStart - wgPacketLength
	paddingHeadroom := rearHeadroom - chacha20poly1305.Overhead
	var paddingLen int
	if paddingHeadroom > 0 {
		paddingLen = h.rng.Intn(paddingHeadroom) + 1
	}

	// Calculate offsets.
	swgpPacketStart = wgPacketStart - 2 - chacha20poly1305.NonceSizeX
	swgpPacketLength = chacha20poly1305.NonceSizeX + 2 + wgPacketLength + paddingLen + chacha20poly1305.Overhead

	nonce := buf[swgpPacketStart : wgPacketStart-2]
	payloadLength := buf[wgPacketStart-2 : wgPacketStart]
	plaintext := buf[wgPacketStart-2 : wgPacketStart+wgPacketLength+paddingLen]

	// Write random nonce.
	_, err = rand.Read(nonce)
	if err != nil {
		return
	}

	// Write payload length.
	binary.BigEndian.PutUint16(payloadLength, uint16(wgPacketLength))

	// AEAD seal.
	h.aead.Seal(nonce, nonce, plaintext, nil)

	return
}

// DecryptZeroCopy implements the Handler DecryptZeroCopy method.
func (h *paranoidHandler) DecryptZeroCopy(buf []byte, swgpPacketStart, swgpPacketLength int) (wgPacketStart, wgPacketLength int, err error) {
	if swgpPacketLength < chacha20poly1305.NonceSizeX+2+1+chacha20poly1305.Overhead {
		err = &HandlerErr{ErrPacketSize, fmt.Sprintf("swgp packet (length %d) is too short", swgpPacketLength)}
		return
	}

	nonce := buf[swgpPacketStart : swgpPacketStart+chacha20poly1305.NonceSizeX]
	ciphertext := buf[swgpPacketStart+chacha20poly1305.NonceSizeX : swgpPacketStart+swgpPacketLength]

	// AEAD open.
	plaintext, err := h.aead.Open(ciphertext[:0], nonce, ciphertext, nil)
	if err != nil {
		return
	}

	// Read and validate payload length.
	payloadLengthBuf := plaintext[:2]
	payloadLength := int(binary.BigEndian.Uint16(payloadLengthBuf))
	if payloadLength > len(plaintext)-2 {
		err = &HandlerErr{ErrPayloadLength, fmt.Sprintf("payload length field value %d is out of range", payloadLength)}
		return
	}

	wgPacketStart = swgpPacketStart + chacha20poly1305.NonceSizeX + 2
	wgPacketLength = payloadLength
	return
}
